.class public final Lvy/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lvy/v;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lvy/v;)V
    .locals 0

    .line 1
    iput p1, p0, Lvy/m;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lvy/m;->g:Lvy/v;

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
    iget v0, p0, Lvy/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lvy/m;

    .line 7
    .line 8
    iget-object p0, p0, Lvy/m;->g:Lvy/v;

    .line 9
    .line 10
    const/4 v1, 0x4

    .line 11
    invoke-direct {v0, v1, p2, p0}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lvy/m;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lvy/m;

    .line 18
    .line 19
    iget-object p0, p0, Lvy/m;->g:Lvy/v;

    .line 20
    .line 21
    const/4 v1, 0x3

    .line 22
    invoke-direct {v0, v1, p2, p0}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lvy/m;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lvy/m;

    .line 29
    .line 30
    iget-object p0, p0, Lvy/m;->g:Lvy/v;

    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    invoke-direct {v0, v1, p2, p0}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lvy/m;->f:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lvy/m;

    .line 40
    .line 41
    iget-object p0, p0, Lvy/m;->g:Lvy/v;

    .line 42
    .line 43
    const/4 v1, 0x1

    .line 44
    invoke-direct {v0, v1, p2, p0}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Lvy/m;->f:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_3
    new-instance v0, Lvy/m;

    .line 51
    .line 52
    iget-object p0, p0, Lvy/m;->g:Lvy/v;

    .line 53
    .line 54
    const/4 v1, 0x0

    .line 55
    invoke-direct {v0, v1, p2, p0}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 56
    .line 57
    .line 58
    iput-object p1, v0, Lvy/m;->f:Ljava/lang/Object;

    .line 59
    .line 60
    return-object v0

    .line 61
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
    iget v0, p0, Lvy/m;->d:I

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
    invoke-virtual {p0, p1, p2}, Lvy/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lvy/m;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lvy/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lvy/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lvy/m;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lvy/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lvy/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lvy/m;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lvy/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Llx0/r;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Lvy/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lvy/m;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lvy/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_3
    check-cast p1, Lvy0/b0;

    .line 75
    .line 76
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    invoke-virtual {p0, p1, p2}, Lvy/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lvy/m;

    .line 83
    .line 84
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lvy/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lvy/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lvy/m;->e:I

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    if-ne v2, v3, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    new-instance p1, Lvy/i;

    .line 35
    .line 36
    const/4 v2, 0x2

    .line 37
    iget-object v4, p0, Lvy/m;->g:Lvy/v;

    .line 38
    .line 39
    invoke-direct {p1, v4, v2}, Lvy/i;-><init>(Lvy/v;I)V

    .line 40
    .line 41
    .line 42
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 43
    .line 44
    .line 45
    iget-object p1, v4, Lvy/v;->r:Lty/k;

    .line 46
    .line 47
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    check-cast p1, Lyy0/i;

    .line 52
    .line 53
    new-instance v0, Lvy/r;

    .line 54
    .line 55
    invoke-direct {v0, v4, v2}, Lvy/r;-><init>(Lvy/v;I)V

    .line 56
    .line 57
    .line 58
    const/4 v2, 0x0

    .line 59
    iput-object v2, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 60
    .line 61
    iput v3, p0, Lvy/m;->e:I

    .line 62
    .line 63
    invoke-interface {p1, v0, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    if-ne p0, v1, :cond_2

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    :goto_0
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    :goto_1
    return-object v1

    .line 73
    :pswitch_0
    iget-object v0, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v0, Lvy0/b0;

    .line 76
    .line 77
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 78
    .line 79
    iget v2, p0, Lvy/m;->e:I

    .line 80
    .line 81
    const/4 v3, 0x1

    .line 82
    if-eqz v2, :cond_4

    .line 83
    .line 84
    if-ne v2, v3, :cond_3

    .line 85
    .line 86
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 91
    .line 92
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 93
    .line 94
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p0

    .line 98
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    iget-object p1, p0, Lvy/m;->g:Lvy/v;

    .line 102
    .line 103
    iget-object v2, p1, Lvy/v;->n:Lty/c;

    .line 104
    .line 105
    new-instance v4, Lty/b;

    .line 106
    .line 107
    const/4 v5, 0x0

    .line 108
    invoke-direct {v4, v5}, Lty/b;-><init>(Z)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v2, v4}, Lty/c;->a(Lty/b;)Lzy0/j;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    new-instance v4, Lvy/l;

    .line 116
    .line 117
    const/4 v5, 0x2

    .line 118
    const/4 v6, 0x0

    .line 119
    invoke-direct {v4, p1, v0, v6, v5}, Lvy/l;-><init>(Lvy/v;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 120
    .line 121
    .line 122
    invoke-static {v4, v2}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    new-instance v2, Lvy/r;

    .line 127
    .line 128
    const/4 v4, 0x1

    .line 129
    invoke-direct {v2, p1, v4}, Lvy/r;-><init>(Lvy/v;I)V

    .line 130
    .line 131
    .line 132
    iput-object v6, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 133
    .line 134
    iput v3, p0, Lvy/m;->e:I

    .line 135
    .line 136
    invoke-virtual {v0, v2, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    if-ne p0, v1, :cond_5

    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_5
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 144
    .line 145
    :goto_3
    return-object v1

    .line 146
    :pswitch_1
    iget-object v0, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v0, Lvy0/b0;

    .line 149
    .line 150
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 151
    .line 152
    iget v2, p0, Lvy/m;->e:I

    .line 153
    .line 154
    const/4 v3, 0x1

    .line 155
    if-eqz v2, :cond_7

    .line 156
    .line 157
    if-ne v2, v3, :cond_6

    .line 158
    .line 159
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    goto :goto_4

    .line 163
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 164
    .line 165
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 166
    .line 167
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    throw p0

    .line 171
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    new-instance p1, Lvy/i;

    .line 175
    .line 176
    const/4 v2, 0x1

    .line 177
    iget-object v4, p0, Lvy/m;->g:Lvy/v;

    .line 178
    .line 179
    invoke-direct {p1, v4, v2}, Lvy/i;-><init>(Lvy/v;I)V

    .line 180
    .line 181
    .line 182
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 183
    .line 184
    .line 185
    iget-object p1, v4, Lvy/v;->o:Lty/h;

    .line 186
    .line 187
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    check-cast p1, Lyy0/i;

    .line 192
    .line 193
    invoke-static {p1}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 194
    .line 195
    .line 196
    move-result-object p1

    .line 197
    invoke-static {p1, v3}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 198
    .line 199
    .line 200
    move-result-object p1

    .line 201
    new-instance v0, Lvy/q;

    .line 202
    .line 203
    const/4 v5, 0x0

    .line 204
    invoke-direct {v0, v2, v5, v4}, Lvy/q;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 205
    .line 206
    .line 207
    invoke-static {p1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 208
    .line 209
    .line 210
    move-result-object p1

    .line 211
    new-instance v0, Lvy/q;

    .line 212
    .line 213
    const/4 v2, 0x2

    .line 214
    invoke-direct {v0, v2, v5, v4}, Lvy/q;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 215
    .line 216
    .line 217
    invoke-static {p1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 218
    .line 219
    .line 220
    move-result-object p1

    .line 221
    new-instance v0, Lvy/r;

    .line 222
    .line 223
    const/4 v2, 0x0

    .line 224
    invoke-direct {v0, v4, v2}, Lvy/r;-><init>(Lvy/v;I)V

    .line 225
    .line 226
    .line 227
    iput-object v5, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 228
    .line 229
    iput v3, p0, Lvy/m;->e:I

    .line 230
    .line 231
    invoke-virtual {p1, v0, p0}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    if-ne p0, v1, :cond_8

    .line 236
    .line 237
    goto :goto_5

    .line 238
    :cond_8
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 239
    .line 240
    :goto_5
    return-object v1

    .line 241
    :pswitch_2
    iget-object v0, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 242
    .line 243
    check-cast v0, Llx0/r;

    .line 244
    .line 245
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 246
    .line 247
    iget v2, p0, Lvy/m;->e:I

    .line 248
    .line 249
    const/4 v3, 0x1

    .line 250
    if-eqz v2, :cond_a

    .line 251
    .line 252
    if-ne v2, v3, :cond_9

    .line 253
    .line 254
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    goto :goto_6

    .line 258
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 259
    .line 260
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 261
    .line 262
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 263
    .line 264
    .line 265
    throw p0

    .line 266
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    iget-object p1, v0, Llx0/r;->d:Ljava/lang/Object;

    .line 270
    .line 271
    move-object v6, p1

    .line 272
    check-cast v6, Lne0/s;

    .line 273
    .line 274
    iget-object p1, v0, Llx0/r;->e:Ljava/lang/Object;

    .line 275
    .line 276
    move-object v7, p1

    .line 277
    check-cast v7, Lcn0/c;

    .line 278
    .line 279
    iget-object p1, v0, Llx0/r;->f:Ljava/lang/Object;

    .line 280
    .line 281
    move-object v8, p1

    .line 282
    check-cast v8, Lcn0/c;

    .line 283
    .line 284
    new-instance v4, La71/b0;

    .line 285
    .line 286
    const/4 v9, 0x0

    .line 287
    const/4 v10, 0x5

    .line 288
    iget-object v5, p0, Lvy/m;->g:Lvy/v;

    .line 289
    .line 290
    invoke-direct/range {v4 .. v10}, La71/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 291
    .line 292
    .line 293
    const/4 p1, 0x0

    .line 294
    iput-object p1, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 295
    .line 296
    iput v3, p0, Lvy/m;->e:I

    .line 297
    .line 298
    invoke-static {v4, p0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    if-ne p0, v1, :cond_b

    .line 303
    .line 304
    goto :goto_7

    .line 305
    :cond_b
    :goto_6
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 306
    .line 307
    :goto_7
    return-object v1

    .line 308
    :pswitch_3
    iget-object v0, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 309
    .line 310
    check-cast v0, Lvy0/b0;

    .line 311
    .line 312
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 313
    .line 314
    iget v2, p0, Lvy/m;->e:I

    .line 315
    .line 316
    const/4 v3, 0x1

    .line 317
    if-eqz v2, :cond_d

    .line 318
    .line 319
    if-ne v2, v3, :cond_c

    .line 320
    .line 321
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 322
    .line 323
    .line 324
    goto :goto_8

    .line 325
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 326
    .line 327
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 328
    .line 329
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 330
    .line 331
    .line 332
    throw p0

    .line 333
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 334
    .line 335
    .line 336
    iget-object p1, p0, Lvy/m;->g:Lvy/v;

    .line 337
    .line 338
    iget-object v2, p1, Lvy/v;->j:Lgb0/y;

    .line 339
    .line 340
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v2

    .line 344
    check-cast v2, Lyy0/i;

    .line 345
    .line 346
    sget-object v4, Lss0/e;->f:Lss0/e;

    .line 347
    .line 348
    new-instance v5, Lvy/j;

    .line 349
    .line 350
    const/4 v6, 0x0

    .line 351
    const/4 v7, 0x0

    .line 352
    invoke-direct {v5, v6, v7, p1}, Lvy/j;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 353
    .line 354
    .line 355
    invoke-static {v2, v4, v5}, Lkp/u6;->e(Lyy0/i;Lss0/e;Lay0/n;)Lzy0/j;

    .line 356
    .line 357
    .line 358
    move-result-object v2

    .line 359
    new-instance v5, Lvy/j;

    .line 360
    .line 361
    const/4 v6, 0x1

    .line 362
    invoke-direct {v5, v6, v7, p1}, Lvy/j;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 363
    .line 364
    .line 365
    invoke-static {v2, v4, v5}, Llp/rf;->c(Lzy0/j;Lss0/e;Lay0/n;)Lzy0/j;

    .line 366
    .line 367
    .line 368
    move-result-object v2

    .line 369
    new-instance v4, Lvy/l;

    .line 370
    .line 371
    const/4 v5, 0x0

    .line 372
    invoke-direct {v4, p1, v0, v7, v5}, Lvy/l;-><init>(Lvy/v;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 373
    .line 374
    .line 375
    iput-object v7, p0, Lvy/m;->f:Ljava/lang/Object;

    .line 376
    .line 377
    iput v3, p0, Lvy/m;->e:I

    .line 378
    .line 379
    invoke-static {v4, p0, v2}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object p0

    .line 383
    if-ne p0, v1, :cond_e

    .line 384
    .line 385
    goto :goto_9

    .line 386
    :cond_e
    :goto_8
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 387
    .line 388
    :goto_9
    return-object v1

    .line 389
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
