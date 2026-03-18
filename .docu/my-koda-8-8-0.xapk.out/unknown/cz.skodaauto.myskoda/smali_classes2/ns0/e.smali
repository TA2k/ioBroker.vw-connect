.class public final Lns0/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lns0/f;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lns0/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lns0/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lns0/e;->f:Lns0/f;

    .line 4
    .line 5
    iput-object p2, p0, Lns0/e;->g:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Lns0/e;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lns0/e;

    .line 7
    .line 8
    iget-object v0, p0, Lns0/e;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    iget-object p0, p0, Lns0/e;->f:Lns0/f;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lns0/e;-><init>(Lns0/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lns0/e;

    .line 18
    .line 19
    iget-object v0, p0, Lns0/e;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    iget-object p0, p0, Lns0/e;->f:Lns0/f;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lns0/e;-><init>(Lns0/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Lns0/e;

    .line 29
    .line 30
    iget-object v0, p0, Lns0/e;->g:Ljava/lang/String;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    iget-object p0, p0, Lns0/e;->f:Lns0/f;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Lns0/e;-><init>(Lns0/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

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
    iget v0, p0, Lns0/e;->d:I

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
    invoke-virtual {p0, p1, p2}, Lns0/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lns0/e;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lns0/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lns0/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lns0/e;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lns0/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lns0/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lns0/e;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lns0/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 12

    .line 1
    iget v0, p0, Lns0/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lns0/e;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, p0, Lns0/e;->f:Lns0/f;

    .line 33
    .line 34
    iget-object v1, p1, Lns0/f;->m:Lks0/g;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    const-string v4, "input"

    .line 40
    .line 41
    iget-object v5, p0, Lns0/e;->g:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v1, v1, Lks0/g;->a:Lbd0/c;

    .line 47
    .line 48
    iget-object v1, v1, Lbd0/c;->a:Lbd0/a;

    .line 49
    .line 50
    new-instance v7, Ljava/net/URL;

    .line 51
    .line 52
    invoke-direct {v7, v5}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    move-object v6, v1

    .line 56
    check-cast v6, Lzc0/b;

    .line 57
    .line 58
    const/4 v8, 0x0

    .line 59
    const/4 v9, 0x0

    .line 60
    const/4 v10, 0x0

    .line 61
    const/4 v11, 0x0

    .line 62
    invoke-virtual/range {v6 .. v11}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    new-instance v4, Lns0/b;

    .line 67
    .line 68
    const/4 v5, 0x2

    .line 69
    invoke-direct {v4, p1, v5}, Lns0/b;-><init>(Lns0/f;I)V

    .line 70
    .line 71
    .line 72
    iput v3, p0, Lns0/e;->e:I

    .line 73
    .line 74
    new-instance p1, Lkf0/x;

    .line 75
    .line 76
    const/4 v3, 0x3

    .line 77
    invoke-direct {p1, v4, v3}, Lkf0/x;-><init>(Lyy0/j;I)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v1, p1, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 85
    .line 86
    if-ne p0, p1, :cond_2

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_2
    move-object p0, v2

    .line 90
    :goto_0
    if-ne p0, v0, :cond_3

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_3
    :goto_1
    move-object v0, v2

    .line 94
    :goto_2
    return-object v0

    .line 95
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 96
    .line 97
    iget v1, p0, Lns0/e;->e:I

    .line 98
    .line 99
    iget-object v2, p0, Lns0/e;->f:Lns0/f;

    .line 100
    .line 101
    const/4 v3, 0x2

    .line 102
    const/4 v4, 0x1

    .line 103
    if-eqz v1, :cond_6

    .line 104
    .line 105
    if-eq v1, v4, :cond_5

    .line 106
    .line 107
    if-ne v1, v3, :cond_4

    .line 108
    .line 109
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    goto :goto_4

    .line 113
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 114
    .line 115
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 116
    .line 117
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    throw p0

    .line 121
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    iget-object p1, v2, Lns0/f;->l:Lks0/i;

    .line 129
    .line 130
    iput v4, p0, Lns0/e;->e:I

    .line 131
    .line 132
    iget-object v1, p0, Lns0/e;->g:Ljava/lang/String;

    .line 133
    .line 134
    invoke-virtual {p1, v1, p0}, Lks0/i;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    if-ne p1, v0, :cond_7

    .line 139
    .line 140
    goto :goto_5

    .line 141
    :cond_7
    :goto_3
    check-cast p1, Lyy0/i;

    .line 142
    .line 143
    new-instance v1, Lns0/b;

    .line 144
    .line 145
    const/4 v4, 0x1

    .line 146
    invoke-direct {v1, v2, v4}, Lns0/b;-><init>(Lns0/f;I)V

    .line 147
    .line 148
    .line 149
    iput v3, p0, Lns0/e;->e:I

    .line 150
    .line 151
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    if-ne p0, v0, :cond_8

    .line 156
    .line 157
    goto :goto_5

    .line 158
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 159
    .line 160
    :goto_5
    return-object v0

    .line 161
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 162
    .line 163
    iget v1, p0, Lns0/e;->e:I

    .line 164
    .line 165
    iget-object v2, p0, Lns0/e;->f:Lns0/f;

    .line 166
    .line 167
    const/4 v3, 0x2

    .line 168
    const/4 v4, 0x1

    .line 169
    if-eqz v1, :cond_b

    .line 170
    .line 171
    if-eq v1, v4, :cond_a

    .line 172
    .line 173
    if-ne v1, v3, :cond_9

    .line 174
    .line 175
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    goto :goto_7

    .line 179
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 180
    .line 181
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 182
    .line 183
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw p0

    .line 187
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    goto :goto_6

    .line 191
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    iget-object p1, v2, Lns0/f;->i:Lks0/v;

    .line 195
    .line 196
    iput v4, p0, Lns0/e;->e:I

    .line 197
    .line 198
    iget-object v1, p0, Lns0/e;->g:Ljava/lang/String;

    .line 199
    .line 200
    invoke-virtual {p1, v1, p0}, Lks0/v;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    if-ne p1, v0, :cond_c

    .line 205
    .line 206
    goto :goto_8

    .line 207
    :cond_c
    :goto_6
    check-cast p1, Lyy0/i;

    .line 208
    .line 209
    iput v3, p0, Lns0/e;->e:I

    .line 210
    .line 211
    invoke-static {p1, p0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    if-ne p1, v0, :cond_d

    .line 216
    .line 217
    goto :goto_8

    .line 218
    :cond_d
    :goto_7
    check-cast p1, Lne0/t;

    .line 219
    .line 220
    instance-of p0, p1, Lne0/c;

    .line 221
    .line 222
    if-eqz p0, :cond_e

    .line 223
    .line 224
    check-cast p1, Lne0/c;

    .line 225
    .line 226
    iget-object p0, v2, Lns0/f;->p:Lzd0/a;

    .line 227
    .line 228
    invoke-virtual {p0, p1}, Lzd0/a;->a(Lne0/t;)V

    .line 229
    .line 230
    .line 231
    :cond_e
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 232
    .line 233
    :goto_8
    return-object v0

    .line 234
    nop

    .line 235
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
