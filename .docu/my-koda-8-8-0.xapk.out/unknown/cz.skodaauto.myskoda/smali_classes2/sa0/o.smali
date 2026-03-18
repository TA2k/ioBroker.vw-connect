.class public final Lsa0/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lsa0/s;


# direct methods
.method public synthetic constructor <init>(Lsa0/s;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lsa0/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsa0/o;->f:Lsa0/s;

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
    iget p1, p0, Lsa0/o;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lsa0/o;

    .line 7
    .line 8
    iget-object p0, p0, Lsa0/o;->f:Lsa0/s;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lsa0/o;-><init>(Lsa0/s;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lsa0/o;

    .line 16
    .line 17
    iget-object p0, p0, Lsa0/o;->f:Lsa0/s;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lsa0/o;-><init>(Lsa0/s;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lsa0/o;

    .line 25
    .line 26
    iget-object p0, p0, Lsa0/o;->f:Lsa0/s;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lsa0/o;-><init>(Lsa0/s;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lsa0/o;->d:I

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
    invoke-virtual {p0, p1, p2}, Lsa0/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lsa0/o;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lsa0/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lsa0/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lsa0/o;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lsa0/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lsa0/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lsa0/o;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lsa0/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 14

    .line 1
    iget v0, p0, Lsa0/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lsa0/o;->e:I

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
    iget-object p1, p0, Lsa0/o;->f:Lsa0/s;

    .line 31
    .line 32
    iget-object v1, p1, Lsa0/s;->l:Lcs0/t;

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
    new-instance v3, Lsa0/l;

    .line 41
    .line 42
    const/4 v4, 0x2

    .line 43
    invoke-direct {v3, p1, v4}, Lsa0/l;-><init>(Lsa0/s;I)V

    .line 44
    .line 45
    .line 46
    iput v2, p0, Lsa0/o;->e:I

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
    iget v1, p0, Lsa0/o;->e:I

    .line 61
    .line 62
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    const/4 v3, 0x1

    .line 65
    if-eqz v1, :cond_5

    .line 66
    .line 67
    if-ne v1, v3, :cond_4

    .line 68
    .line 69
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    :cond_3
    move-object v0, v2

    .line 73
    goto :goto_3

    .line 74
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 75
    .line 76
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iget-object p1, p0, Lsa0/o;->f:Lsa0/s;

    .line 86
    .line 87
    iget-object v1, p1, Lsa0/s;->q:Lqa0/d;

    .line 88
    .line 89
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    check-cast v1, Lyy0/i;

    .line 94
    .line 95
    new-instance v4, Lsa0/l;

    .line 96
    .line 97
    const/4 v5, 0x1

    .line 98
    invoke-direct {v4, p1, v5}, Lsa0/l;-><init>(Lsa0/s;I)V

    .line 99
    .line 100
    .line 101
    iput v3, p0, Lsa0/o;->e:I

    .line 102
    .line 103
    new-instance p1, Lwk0/o0;

    .line 104
    .line 105
    const/16 v3, 0x11

    .line 106
    .line 107
    invoke-direct {p1, v4, v3}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 108
    .line 109
    .line 110
    invoke-interface {v1, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    if-ne p0, v0, :cond_6

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_6
    move-object p0, v2

    .line 118
    :goto_2
    if-ne p0, v0, :cond_3

    .line 119
    .line 120
    :goto_3
    return-object v0

    .line 121
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 122
    .line 123
    iget v1, p0, Lsa0/o;->e:I

    .line 124
    .line 125
    const/4 v2, 0x2

    .line 126
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 127
    .line 128
    const/4 v4, 0x1

    .line 129
    iget-object v5, p0, Lsa0/o;->f:Lsa0/s;

    .line 130
    .line 131
    if-eqz v1, :cond_a

    .line 132
    .line 133
    if-eq v1, v4, :cond_9

    .line 134
    .line 135
    if-ne v1, v2, :cond_8

    .line 136
    .line 137
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    :cond_7
    move-object v0, v3

    .line 141
    goto :goto_8

    .line 142
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 143
    .line 144
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 145
    .line 146
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    throw p0

    .line 150
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    goto :goto_4

    .line 154
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    iget-object p1, v5, Lsa0/s;->m:Lgb0/h;

    .line 158
    .line 159
    iput v4, p0, Lsa0/o;->e:I

    .line 160
    .line 161
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 162
    .line 163
    .line 164
    invoke-virtual {p1, p0}, Lgb0/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    if-ne p1, v0, :cond_b

    .line 169
    .line 170
    goto :goto_8

    .line 171
    :cond_b
    :goto_4
    check-cast p1, Lne0/t;

    .line 172
    .line 173
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    move-object v6, v1

    .line 178
    check-cast v6, Lsa0/p;

    .line 179
    .line 180
    instance-of v1, p1, Lne0/e;

    .line 181
    .line 182
    if-eqz v1, :cond_c

    .line 183
    .line 184
    check-cast p1, Lne0/e;

    .line 185
    .line 186
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 187
    .line 188
    sget-object v1, Lhb0/a;->d:Lhb0/a;

    .line 189
    .line 190
    if-ne p1, v1, :cond_c

    .line 191
    .line 192
    :goto_5
    move v7, v4

    .line 193
    goto :goto_6

    .line 194
    :cond_c
    const/4 v4, 0x0

    .line 195
    goto :goto_5

    .line 196
    :goto_6
    const/4 v12, 0x0

    .line 197
    const/16 v13, 0x3e

    .line 198
    .line 199
    const/4 v8, 0x0

    .line 200
    const/4 v9, 0x0

    .line 201
    const/4 v10, 0x0

    .line 202
    const/4 v11, 0x0

    .line 203
    invoke-static/range {v6 .. v13}, Lsa0/p;->a(Lsa0/p;ZZZZLjava/lang/String;ZI)Lsa0/p;

    .line 204
    .line 205
    .line 206
    move-result-object p1

    .line 207
    invoke-virtual {v5, p1}, Lql0/j;->g(Lql0/h;)V

    .line 208
    .line 209
    .line 210
    iget-object p1, v5, Lsa0/s;->n:Lkf0/z;

    .line 211
    .line 212
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    check-cast p1, Lyy0/i;

    .line 217
    .line 218
    new-instance v1, Lsa0/l;

    .line 219
    .line 220
    const/4 v4, 0x0

    .line 221
    invoke-direct {v1, v5, v4}, Lsa0/l;-><init>(Lsa0/s;I)V

    .line 222
    .line 223
    .line 224
    iput v2, p0, Lsa0/o;->e:I

    .line 225
    .line 226
    new-instance v2, Lsa0/n;

    .line 227
    .line 228
    invoke-direct {v2, v1, v4}, Lsa0/n;-><init>(Lyy0/j;I)V

    .line 229
    .line 230
    .line 231
    invoke-interface {p1, v2, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    if-ne p0, v0, :cond_d

    .line 236
    .line 237
    goto :goto_7

    .line 238
    :cond_d
    move-object p0, v3

    .line 239
    :goto_7
    if-ne p0, v0, :cond_7

    .line 240
    .line 241
    :goto_8
    return-object v0

    .line 242
    nop

    .line 243
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
