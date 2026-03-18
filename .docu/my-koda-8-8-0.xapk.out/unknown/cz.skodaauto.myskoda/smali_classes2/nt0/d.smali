.class public final Lnt0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lnt0/i;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V
    .locals 0

    .line 1
    iput p1, p0, Lnt0/d;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lnt0/d;->f:Lnt0/i;

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
    iget p1, p0, Lnt0/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lnt0/d;

    .line 7
    .line 8
    iget-object p0, p0, Lnt0/d;->f:Lnt0/i;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, v0, p2, p0}, Lnt0/d;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lnt0/d;

    .line 16
    .line 17
    iget-object p0, p0, Lnt0/d;->f:Lnt0/i;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, v0, p2, p0}, Lnt0/d;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lnt0/d;

    .line 25
    .line 26
    iget-object p0, p0, Lnt0/d;->f:Lnt0/i;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, v0, p2, p0}, Lnt0/d;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lnt0/d;

    .line 34
    .line 35
    iget-object p0, p0, Lnt0/d;->f:Lnt0/i;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, v0, p2, p0}, Lnt0/d;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

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
    iget v0, p0, Lnt0/d;->d:I

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
    invoke-virtual {p0, p1, p2}, Lnt0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnt0/d;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnt0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lnt0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lnt0/d;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lnt0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lnt0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lnt0/d;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lnt0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lnt0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lnt0/d;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lnt0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lnt0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lnt0/d;->e:I

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
    iget-object p1, p0, Lnt0/d;->f:Lnt0/i;

    .line 31
    .line 32
    iget-object v1, p1, Lnt0/i;->p:Lrs0/g;

    .line 33
    .line 34
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Lyy0/i;

    .line 39
    .line 40
    new-instance v3, Lnt0/c;

    .line 41
    .line 42
    const/4 v4, 0x4

    .line 43
    invoke-direct {v3, p1, v4}, Lnt0/c;-><init>(Lnt0/i;I)V

    .line 44
    .line 45
    .line 46
    iput v2, p0, Lnt0/d;->e:I

    .line 47
    .line 48
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    if-ne p0, v0, :cond_2

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    :goto_1
    return-object v0

    .line 58
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 59
    .line 60
    iget v1, p0, Lnt0/d;->e:I

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    if-eqz v1, :cond_4

    .line 64
    .line 65
    if-ne v1, v2, :cond_3

    .line 66
    .line 67
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 72
    .line 73
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 74
    .line 75
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p0

    .line 79
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object p1, p0, Lnt0/d;->f:Lnt0/i;

    .line 83
    .line 84
    iget-object v1, p1, Lnt0/i;->m:Ltj0/a;

    .line 85
    .line 86
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    check-cast v1, Lyy0/i;

    .line 91
    .line 92
    new-instance v3, Lnt0/c;

    .line 93
    .line 94
    const/4 v4, 0x3

    .line 95
    invoke-direct {v3, p1, v4}, Lnt0/c;-><init>(Lnt0/i;I)V

    .line 96
    .line 97
    .line 98
    iput v2, p0, Lnt0/d;->e:I

    .line 99
    .line 100
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    if-ne p0, v0, :cond_5

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    :goto_3
    return-object v0

    .line 110
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 111
    .line 112
    iget v1, p0, Lnt0/d;->e:I

    .line 113
    .line 114
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    iget-object v3, p0, Lnt0/d;->f:Lnt0/i;

    .line 117
    .line 118
    const/4 v4, 0x1

    .line 119
    if-eqz v1, :cond_7

    .line 120
    .line 121
    if-ne v1, v4, :cond_6

    .line 122
    .line 123
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    goto :goto_4

    .line 127
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 128
    .line 129
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 130
    .line 131
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw p0

    .line 135
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    iget-object p1, v3, Lnt0/i;->q:Lqf0/g;

    .line 139
    .line 140
    iput v4, p0, Lnt0/d;->e:I

    .line 141
    .line 142
    invoke-virtual {p1, v2, p0}, Lqf0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    if-ne p1, v0, :cond_8

    .line 147
    .line 148
    goto :goto_5

    .line 149
    :cond_8
    :goto_4
    check-cast p1, Ljava/lang/Boolean;

    .line 150
    .line 151
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    move-object v5, p1

    .line 160
    check-cast v5, Lnt0/e;

    .line 161
    .line 162
    xor-int/lit8 v12, p0, 0x1

    .line 163
    .line 164
    const/16 v13, 0x3f

    .line 165
    .line 166
    const/4 v6, 0x0

    .line 167
    const/4 v7, 0x0

    .line 168
    const/4 v8, 0x0

    .line 169
    const/4 v9, 0x0

    .line 170
    const/4 v10, 0x0

    .line 171
    const/4 v11, 0x0

    .line 172
    invoke-static/range {v5 .. v13}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    invoke-virtual {v3, p0}, Lql0/j;->g(Lql0/h;)V

    .line 177
    .line 178
    .line 179
    move-object v0, v2

    .line 180
    :goto_5
    return-object v0

    .line 181
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 182
    .line 183
    iget v1, p0, Lnt0/d;->e:I

    .line 184
    .line 185
    const/4 v2, 0x1

    .line 186
    if-eqz v1, :cond_a

    .line 187
    .line 188
    if-ne v1, v2, :cond_9

    .line 189
    .line 190
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    goto :goto_6

    .line 194
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 195
    .line 196
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 197
    .line 198
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    throw p0

    .line 202
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 203
    .line 204
    .line 205
    iget-object p1, p0, Lnt0/d;->f:Lnt0/i;

    .line 206
    .line 207
    iget-object v1, p1, Lnt0/i;->p:Lrs0/g;

    .line 208
    .line 209
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    check-cast v1, Lyy0/i;

    .line 214
    .line 215
    new-instance v3, Lnt0/c;

    .line 216
    .line 217
    const/4 v4, 0x0

    .line 218
    invoke-direct {v3, p1, v4}, Lnt0/c;-><init>(Lnt0/i;I)V

    .line 219
    .line 220
    .line 221
    iput v2, p0, Lnt0/d;->e:I

    .line 222
    .line 223
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    if-ne p0, v0, :cond_b

    .line 228
    .line 229
    goto :goto_7

    .line 230
    :cond_b
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 231
    .line 232
    :goto_7
    return-object v0

    .line 233
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
