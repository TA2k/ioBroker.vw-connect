.class public final Lc80/a0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc80/d0;


# direct methods
.method public synthetic constructor <init>(Lc80/d0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc80/a0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc80/a0;->f:Lc80/d0;

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
    iget p1, p0, Lc80/a0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc80/a0;

    .line 7
    .line 8
    iget-object p0, p0, Lc80/a0;->f:Lc80/d0;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lc80/a0;-><init>(Lc80/d0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc80/a0;

    .line 16
    .line 17
    iget-object p0, p0, Lc80/a0;->f:Lc80/d0;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lc80/a0;-><init>(Lc80/d0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lc80/a0;

    .line 25
    .line 26
    iget-object p0, p0, Lc80/a0;->f:Lc80/d0;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lc80/a0;-><init>(Lc80/d0;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lc80/a0;

    .line 34
    .line 35
    iget-object p0, p0, Lc80/a0;->f:Lc80/d0;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lc80/a0;-><init>(Lc80/d0;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lc80/a0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc80/a0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc80/a0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc80/a0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc80/a0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc80/a0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc80/a0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lc80/a0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lc80/a0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lc80/a0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lc80/a0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lc80/a0;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lc80/a0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 8

    .line 1
    iget v0, p0, Lc80/a0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    iget-object v4, p0, Lc80/a0;->f:Lc80/d0;

    .line 8
    .line 9
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    iget v6, p0, Lc80/a0;->e:I

    .line 17
    .line 18
    if-eqz v6, :cond_2

    .line 19
    .line 20
    if-eq v6, v3, :cond_1

    .line 21
    .line 22
    if-ne v6, v1, :cond_0

    .line 23
    .line 24
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_2

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p1, v4, Lc80/d0;->k:Lwq0/d;

    .line 42
    .line 43
    iput v3, p0, Lc80/a0;->e:I

    .line 44
    .line 45
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, p0}, Lwq0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    if-ne p1, v0, :cond_3

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    :goto_0
    iput v1, p0, Lc80/a0;->e:I

    .line 56
    .line 57
    invoke-static {v4, p0}, Lc80/d0;->h(Lc80/d0;Lrx0/c;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    if-ne p0, v0, :cond_4

    .line 62
    .line 63
    :goto_1
    move-object v5, v0

    .line 64
    :cond_4
    :goto_2
    return-object v5

    .line 65
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 66
    .line 67
    iget v6, p0, Lc80/a0;->e:I

    .line 68
    .line 69
    const/4 v7, 0x3

    .line 70
    if-eqz v6, :cond_7

    .line 71
    .line 72
    if-eq v6, v3, :cond_6

    .line 73
    .line 74
    if-eq v6, v1, :cond_6

    .line 75
    .line 76
    if-ne v6, v7, :cond_5

    .line 77
    .line 78
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_5

    .line 82
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 83
    .line 84
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    sget-object p1, Lc80/d0;->n:Ljava/util/List;

    .line 96
    .line 97
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    check-cast p1, Lc80/b0;

    .line 102
    .line 103
    iget-boolean p1, p1, Lc80/b0;->c:Z

    .line 104
    .line 105
    if-eqz p1, :cond_8

    .line 106
    .line 107
    iget-object p1, v4, Lc80/d0;->j:Lwq0/a0;

    .line 108
    .line 109
    iput v3, p0, Lc80/a0;->e:I

    .line 110
    .line 111
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 112
    .line 113
    .line 114
    invoke-virtual {p1, p0}, Lwq0/a0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    if-ne p1, v0, :cond_9

    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_8
    iget-object p1, v4, Lc80/d0;->l:Lwq0/e0;

    .line 122
    .line 123
    sget-object v2, Lyq0/n;->d:Lyq0/n;

    .line 124
    .line 125
    iput v1, p0, Lc80/a0;->e:I

    .line 126
    .line 127
    invoke-virtual {p1, v2, p0}, Lwq0/e0;->b(Lyq0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    if-ne p1, v0, :cond_9

    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_9
    :goto_3
    iput v7, p0, Lc80/a0;->e:I

    .line 135
    .line 136
    invoke-static {v4, p0}, Lc80/d0;->h(Lc80/d0;Lrx0/c;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    if-ne p0, v0, :cond_a

    .line 141
    .line 142
    :goto_4
    move-object v5, v0

    .line 143
    :cond_a
    :goto_5
    return-object v5

    .line 144
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 145
    .line 146
    iget v1, p0, Lc80/a0;->e:I

    .line 147
    .line 148
    if-eqz v1, :cond_c

    .line 149
    .line 150
    if-ne v1, v3, :cond_b

    .line 151
    .line 152
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    goto :goto_6

    .line 156
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 157
    .line 158
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    iget-object p1, v4, Lc80/d0;->m:Lwr0/i;

    .line 166
    .line 167
    invoke-virtual {p1}, Lwr0/i;->a()Lyy0/i;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    new-instance v1, Lac0/e;

    .line 172
    .line 173
    const/16 v2, 0xc

    .line 174
    .line 175
    invoke-direct {v1, v4, v2}, Lac0/e;-><init>(Ljava/lang/Object;I)V

    .line 176
    .line 177
    .line 178
    iput v3, p0, Lc80/a0;->e:I

    .line 179
    .line 180
    check-cast p1, Lne0/n;

    .line 181
    .line 182
    invoke-virtual {p1, v1, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    if-ne p0, v0, :cond_d

    .line 187
    .line 188
    move-object v5, v0

    .line 189
    :cond_d
    :goto_6
    return-object v5

    .line 190
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 191
    .line 192
    iget v1, p0, Lc80/a0;->e:I

    .line 193
    .line 194
    if-eqz v1, :cond_f

    .line 195
    .line 196
    if-ne v1, v3, :cond_e

    .line 197
    .line 198
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    goto :goto_7

    .line 202
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 203
    .line 204
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    throw p0

    .line 208
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    iput v3, p0, Lc80/a0;->e:I

    .line 212
    .line 213
    invoke-static {v4, p0}, Lc80/d0;->h(Lc80/d0;Lrx0/c;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    if-ne p0, v0, :cond_10

    .line 218
    .line 219
    move-object v5, v0

    .line 220
    :cond_10
    :goto_7
    return-object v5

    .line 221
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
