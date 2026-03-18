.class public final Lx60/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lx60/o;


# direct methods
.method public synthetic constructor <init>(Lx60/o;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lx60/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lx60/l;->f:Lx60/o;

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
    iget p1, p0, Lx60/l;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lx60/l;

    .line 7
    .line 8
    iget-object p0, p0, Lx60/l;->f:Lx60/o;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lx60/l;-><init>(Lx60/o;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lx60/l;

    .line 16
    .line 17
    iget-object p0, p0, Lx60/l;->f:Lx60/o;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lx60/l;-><init>(Lx60/o;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lx60/l;

    .line 25
    .line 26
    iget-object p0, p0, Lx60/l;->f:Lx60/o;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lx60/l;-><init>(Lx60/o;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lx60/l;

    .line 34
    .line 35
    iget-object p0, p0, Lx60/l;->f:Lx60/o;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lx60/l;-><init>(Lx60/o;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lx60/l;

    .line 43
    .line 44
    iget-object p0, p0, Lx60/l;->f:Lx60/o;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lx60/l;-><init>(Lx60/o;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lx60/l;->d:I

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
    invoke-virtual {p0, p1, p2}, Lx60/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lx60/l;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lx60/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lx60/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lx60/l;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lx60/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lx60/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lx60/l;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lx60/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lx60/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lx60/l;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lx60/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lx60/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lx60/l;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lx60/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lx60/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lx60/l;->e:I

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
    new-instance p1, Lx41/y;

    .line 31
    .line 32
    const/16 v1, 0x1a

    .line 33
    .line 34
    invoke-direct {p1, v1}, Lx41/y;-><init>(I)V

    .line 35
    .line 36
    .line 37
    iget-object v1, p0, Lx60/l;->f:Lx60/o;

    .line 38
    .line 39
    invoke-static {v1, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 40
    .line 41
    .line 42
    iget-object p1, v1, Lx60/o;->l:Lkc0/t0;

    .line 43
    .line 44
    iput v2, p0, Lx60/l;->e:I

    .line 45
    .line 46
    invoke-virtual {p1, p0}, Lkc0/t0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    if-ne p0, v0, :cond_2

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    :goto_1
    return-object v0

    .line 56
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 57
    .line 58
    iget v1, p0, Lx60/l;->e:I

    .line 59
    .line 60
    const/4 v2, 0x1

    .line 61
    if-eqz v1, :cond_4

    .line 62
    .line 63
    if-ne v1, v2, :cond_3

    .line 64
    .line 65
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iget-object p1, p0, Lx60/l;->f:Lx60/o;

    .line 81
    .line 82
    iget-object v1, p1, Lx60/o;->h:Lwr0/c;

    .line 83
    .line 84
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    check-cast v1, Lyy0/i;

    .line 89
    .line 90
    new-instance v3, Lx60/k;

    .line 91
    .line 92
    const/4 v4, 0x1

    .line 93
    invoke-direct {v3, p1, v4}, Lx60/k;-><init>(Lx60/o;I)V

    .line 94
    .line 95
    .line 96
    iput v2, p0, Lx60/l;->e:I

    .line 97
    .line 98
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    if-ne p0, v0, :cond_5

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    :goto_3
    return-object v0

    .line 108
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 109
    .line 110
    iget v1, p0, Lx60/l;->e:I

    .line 111
    .line 112
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 113
    .line 114
    iget-object v3, p0, Lx60/l;->f:Lx60/o;

    .line 115
    .line 116
    const/4 v4, 0x2

    .line 117
    const/4 v5, 0x1

    .line 118
    if-eqz v1, :cond_9

    .line 119
    .line 120
    if-eq v1, v5, :cond_8

    .line 121
    .line 122
    if-ne v1, v4, :cond_7

    .line 123
    .line 124
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    :cond_6
    move-object v0, v2

    .line 128
    goto :goto_5

    .line 129
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 130
    .line 131
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 132
    .line 133
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    throw p0

    .line 137
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    goto :goto_4

    .line 141
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    iget-object p1, v3, Lx60/o;->m:Lwr0/k;

    .line 145
    .line 146
    iput v5, p0, Lx60/l;->e:I

    .line 147
    .line 148
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    invoke-virtual {p1, p0}, Lwr0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    if-ne p1, v0, :cond_a

    .line 156
    .line 157
    goto :goto_5

    .line 158
    :cond_a
    :goto_4
    check-cast p1, Lyy0/i;

    .line 159
    .line 160
    new-instance v1, Lh50/y0;

    .line 161
    .line 162
    const/16 v5, 0x17

    .line 163
    .line 164
    invoke-direct {v1, v3, v5}, Lh50/y0;-><init>(Ljava/lang/Object;I)V

    .line 165
    .line 166
    .line 167
    iput v4, p0, Lx60/l;->e:I

    .line 168
    .line 169
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    if-ne p0, v0, :cond_6

    .line 174
    .line 175
    :goto_5
    return-object v0

    .line 176
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 177
    .line 178
    iget v1, p0, Lx60/l;->e:I

    .line 179
    .line 180
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 181
    .line 182
    const/4 v3, 0x1

    .line 183
    if-eqz v1, :cond_d

    .line 184
    .line 185
    if-ne v1, v3, :cond_c

    .line 186
    .line 187
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    :cond_b
    move-object v0, v2

    .line 191
    goto :goto_6

    .line 192
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 193
    .line 194
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 195
    .line 196
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    throw p0

    .line 200
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    iget-object p1, p0, Lx60/l;->f:Lx60/o;

    .line 204
    .line 205
    iget-object p1, p1, Lx60/o;->m:Lwr0/k;

    .line 206
    .line 207
    iput v3, p0, Lx60/l;->e:I

    .line 208
    .line 209
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 210
    .line 211
    .line 212
    invoke-virtual {p1, p0}, Lwr0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    if-ne p0, v0, :cond_b

    .line 217
    .line 218
    :goto_6
    return-object v0

    .line 219
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 220
    .line 221
    iget v1, p0, Lx60/l;->e:I

    .line 222
    .line 223
    const/4 v2, 0x1

    .line 224
    if-eqz v1, :cond_f

    .line 225
    .line 226
    if-ne v1, v2, :cond_e

    .line 227
    .line 228
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    goto :goto_7

    .line 232
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 233
    .line 234
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 235
    .line 236
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    throw p0

    .line 240
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    iget-object p1, p0, Lx60/l;->f:Lx60/o;

    .line 244
    .line 245
    iget-object v1, p1, Lx60/o;->j:Lwr0/i;

    .line 246
    .line 247
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v1

    .line 251
    check-cast v1, Lyy0/i;

    .line 252
    .line 253
    invoke-static {v1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 254
    .line 255
    .line 256
    move-result-object v1

    .line 257
    new-instance v3, Lx60/k;

    .line 258
    .line 259
    const/4 v4, 0x0

    .line 260
    invoke-direct {v3, p1, v4}, Lx60/k;-><init>(Lx60/o;I)V

    .line 261
    .line 262
    .line 263
    iput v2, p0, Lx60/l;->e:I

    .line 264
    .line 265
    invoke-virtual {v1, v3, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object p0

    .line 269
    if-ne p0, v0, :cond_10

    .line 270
    .line 271
    goto :goto_8

    .line 272
    :cond_10
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 273
    .line 274
    :goto_8
    return-object v0

    .line 275
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
