.class public final Lpv0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lpv0/g;


# direct methods
.method public synthetic constructor <init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lpv0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lpv0/a;->f:Lpv0/g;

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
    iget p1, p0, Lpv0/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lpv0/a;

    .line 7
    .line 8
    iget-object p0, p0, Lpv0/a;->f:Lpv0/g;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lpv0/a;-><init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lpv0/a;

    .line 16
    .line 17
    iget-object p0, p0, Lpv0/a;->f:Lpv0/g;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lpv0/a;-><init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lpv0/a;

    .line 25
    .line 26
    iget-object p0, p0, Lpv0/a;->f:Lpv0/g;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lpv0/a;-><init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lpv0/a;

    .line 34
    .line 35
    iget-object p0, p0, Lpv0/a;->f:Lpv0/g;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lpv0/a;-><init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    nop

    .line 43
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
    iget v0, p0, Lpv0/a;->d:I

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
    invoke-virtual {p0, p1, p2}, Lpv0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lpv0/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lpv0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lpv0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lpv0/a;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lpv0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lpv0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lpv0/a;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lpv0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lpv0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lpv0/a;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lpv0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lpv0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lpv0/a;->e:I

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
    iget-object p1, p0, Lpv0/a;->f:Lpv0/g;

    .line 31
    .line 32
    iget-object p1, p1, Lpv0/g;->r:Llp0/d;

    .line 33
    .line 34
    iput v2, p0, Lpv0/a;->e:I

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    invoke-virtual {p1, v1, p0}, Llp0/d;->b(Lmp0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    if-ne p0, v0, :cond_2

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    :goto_1
    return-object v0

    .line 47
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 48
    .line 49
    iget v1, p0, Lpv0/a;->e:I

    .line 50
    .line 51
    const/4 v2, 0x1

    .line 52
    if-eqz v1, :cond_4

    .line 53
    .line 54
    if-ne v1, v2, :cond_3

    .line 55
    .line 56
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 61
    .line 62
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 63
    .line 64
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    iget-object p1, p0, Lpv0/a;->f:Lpv0/g;

    .line 72
    .line 73
    iget-object v1, p1, Lpv0/g;->q:Llp0/b;

    .line 74
    .line 75
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    check-cast v1, Lyy0/i;

    .line 80
    .line 81
    new-instance v3, Lpv0/c;

    .line 82
    .line 83
    const/4 v4, 0x1

    .line 84
    invoke-direct {v3, p1, v4}, Lpv0/c;-><init>(Lpv0/g;I)V

    .line 85
    .line 86
    .line 87
    iput v2, p0, Lpv0/a;->e:I

    .line 88
    .line 89
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    if-ne p0, v0, :cond_5

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    :goto_3
    return-object v0

    .line 99
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 100
    .line 101
    iget v1, p0, Lpv0/a;->e:I

    .line 102
    .line 103
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    const/4 v3, 0x1

    .line 106
    if-eqz v1, :cond_8

    .line 107
    .line 108
    if-ne v1, v3, :cond_7

    .line 109
    .line 110
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_6
    move-object v0, v2

    .line 114
    goto :goto_5

    .line 115
    :cond_7
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
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    iget-object p1, p0, Lpv0/a;->f:Lpv0/g;

    .line 127
    .line 128
    iget-object v1, p1, Lpv0/g;->l:Lkf0/v;

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
    new-instance v4, Lpv0/c;

    .line 137
    .line 138
    const/4 v5, 0x0

    .line 139
    invoke-direct {v4, p1, v5}, Lpv0/c;-><init>(Lpv0/g;I)V

    .line 140
    .line 141
    .line 142
    iput v3, p0, Lpv0/a;->e:I

    .line 143
    .line 144
    new-instance p1, Lpt0/i;

    .line 145
    .line 146
    const/4 v3, 0x1

    .line 147
    invoke-direct {p1, v4, v3}, Lpt0/i;-><init>(Lyy0/j;I)V

    .line 148
    .line 149
    .line 150
    invoke-interface {v1, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    if-ne p0, v0, :cond_9

    .line 155
    .line 156
    goto :goto_4

    .line 157
    :cond_9
    move-object p0, v2

    .line 158
    :goto_4
    if-ne p0, v0, :cond_6

    .line 159
    .line 160
    :goto_5
    return-object v0

    .line 161
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 162
    .line 163
    iget v1, p0, Lpv0/a;->e:I

    .line 164
    .line 165
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    iget-object v3, p0, Lpv0/a;->f:Lpv0/g;

    .line 168
    .line 169
    const/4 v4, 0x1

    .line 170
    if-eqz v1, :cond_b

    .line 171
    .line 172
    if-ne v1, v4, :cond_a

    .line 173
    .line 174
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    goto :goto_6

    .line 178
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 179
    .line 180
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 181
    .line 182
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    throw p0

    .line 186
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    iget-object p1, v3, Lpv0/g;->h:Lwr0/e;

    .line 190
    .line 191
    iput v4, p0, Lpv0/a;->e:I

    .line 192
    .line 193
    invoke-virtual {p1, v2, p0}, Lwr0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object p1

    .line 197
    if-ne p1, v0, :cond_c

    .line 198
    .line 199
    goto :goto_a

    .line 200
    :cond_c
    :goto_6
    check-cast p1, Lyr0/e;

    .line 201
    .line 202
    if-eqz p1, :cond_d

    .line 203
    .line 204
    iget-object p0, p1, Lyr0/e;->n:Ljava/util/List;

    .line 205
    .line 206
    goto :goto_7

    .line 207
    :cond_d
    const/4 p0, 0x0

    .line 208
    :goto_7
    if-eqz p0, :cond_e

    .line 209
    .line 210
    sget-object p1, Lyr0/f;->k:Lyr0/f;

    .line 211
    .line 212
    invoke-interface {p0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result p0

    .line 216
    :goto_8
    move v8, p0

    .line 217
    goto :goto_9

    .line 218
    :cond_e
    const/4 p0, 0x0

    .line 219
    goto :goto_8

    .line 220
    :goto_9
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    move-object v4, p0

    .line 225
    check-cast v4, Lpv0/f;

    .line 226
    .line 227
    const/4 v12, 0x0

    .line 228
    const/16 v13, 0x1f7

    .line 229
    .line 230
    const/4 v5, 0x0

    .line 231
    const/4 v6, 0x0

    .line 232
    const/4 v7, 0x0

    .line 233
    const/4 v9, 0x0

    .line 234
    const/4 v10, 0x0

    .line 235
    const/4 v11, 0x0

    .line 236
    invoke-static/range {v4 .. v13}, Lpv0/f;->a(Lpv0/f;ZZZZZZLjava/lang/String;ZI)Lpv0/f;

    .line 237
    .line 238
    .line 239
    move-result-object p0

    .line 240
    invoke-virtual {v3, p0}, Lql0/j;->g(Lql0/h;)V

    .line 241
    .line 242
    .line 243
    move-object v0, v2

    .line 244
    :goto_a
    return-object v0

    .line 245
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
