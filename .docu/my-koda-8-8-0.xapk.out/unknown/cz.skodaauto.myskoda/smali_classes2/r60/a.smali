.class public final Lr60/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lr60/g;


# direct methods
.method public synthetic constructor <init>(Lr60/g;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lr60/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr60/a;->f:Lr60/g;

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
    iget p1, p0, Lr60/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lr60/a;

    .line 7
    .line 8
    iget-object p0, p0, Lr60/a;->f:Lr60/g;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lr60/a;-><init>(Lr60/g;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lr60/a;

    .line 16
    .line 17
    iget-object p0, p0, Lr60/a;->f:Lr60/g;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lr60/a;-><init>(Lr60/g;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lr60/a;

    .line 25
    .line 26
    iget-object p0, p0, Lr60/a;->f:Lr60/g;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lr60/a;-><init>(Lr60/g;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lr60/a;->d:I

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
    invoke-virtual {p0, p1, p2}, Lr60/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lr60/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lr60/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lr60/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lr60/a;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lr60/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lr60/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lr60/a;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lr60/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 10

    .line 1
    iget v0, p0, Lr60/a;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x2

    .line 5
    const/4 v3, 0x0

    .line 6
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 7
    .line 8
    iget-object v5, p0, Lr60/a;->f:Lr60/g;

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
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v8, p0, Lr60/a;->e:I

    .line 19
    .line 20
    if-eqz v8, :cond_1

    .line 21
    .line 22
    if-ne v8, v7, :cond_0

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
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iget-object p1, v5, Lr60/g;->k:Lp60/e;

    .line 38
    .line 39
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    check-cast p1, Lyy0/i;

    .line 44
    .line 45
    iget-object v4, v5, Lr60/g;->l:Lnn0/e;

    .line 46
    .line 47
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    check-cast v4, Lyy0/i;

    .line 52
    .line 53
    new-instance v8, Lhk0/a;

    .line 54
    .line 55
    const/4 v9, 0x4

    .line 56
    invoke-direct {v8, v5, v3, v9}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    iput v7, p0, Lr60/a;->e:I

    .line 60
    .line 61
    new-array v2, v2, [Lyy0/i;

    .line 62
    .line 63
    aput-object p1, v2, v1

    .line 64
    .line 65
    aput-object v4, v2, v7

    .line 66
    .line 67
    new-instance p1, Lyy0/g1;

    .line 68
    .line 69
    invoke-direct {p1, v8, v3}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 70
    .line 71
    .line 72
    sget-object v1, Lyy0/h1;->d:Lyy0/h1;

    .line 73
    .line 74
    sget-object v3, Lzy0/q;->d:Lzy0/q;

    .line 75
    .line 76
    invoke-static {v1, p1, p0, v3, v2}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 81
    .line 82
    if-ne p0, p1, :cond_2

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_2
    move-object p0, v6

    .line 86
    :goto_0
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 87
    .line 88
    if-ne p0, p1, :cond_3

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_3
    move-object p0, v6

    .line 92
    :goto_1
    if-ne p0, v0, :cond_4

    .line 93
    .line 94
    move-object v6, v0

    .line 95
    :cond_4
    :goto_2
    return-object v6

    .line 96
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 97
    .line 98
    iget v8, p0, Lr60/a;->e:I

    .line 99
    .line 100
    if-eqz v8, :cond_7

    .line 101
    .line 102
    if-eq v8, v7, :cond_6

    .line 103
    .line 104
    if-ne v8, v2, :cond_5

    .line 105
    .line 106
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 111
    .line 112
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    iget-object p1, v5, Lr60/g;->i:Lp60/b;

    .line 124
    .line 125
    iput v7, p0, Lr60/a;->e:I

    .line 126
    .line 127
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    iget-object v4, p1, Lp60/b;->a:Lln0/l;

    .line 131
    .line 132
    iget-object v7, v4, Lln0/l;->a:Lxl0/f;

    .line 133
    .line 134
    new-instance v8, Lln0/j;

    .line 135
    .line 136
    invoke-direct {v8, v4, v3, v1}, Lln0/j;-><init>(Lln0/l;Lkotlin/coroutines/Continuation;I)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v7, v8}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    iget-object v4, p1, Lp60/b;->b:Lnn0/x;

    .line 144
    .line 145
    sget-object v7, Lon0/c;->d:Lon0/c;

    .line 146
    .line 147
    iget-object v4, v4, Lnn0/x;->a:Lnn0/c;

    .line 148
    .line 149
    check-cast v4, Lln0/c;

    .line 150
    .line 151
    iput-object v7, v4, Lln0/c;->a:Lon0/c;

    .line 152
    .line 153
    iget-object p1, p1, Lp60/b;->c:Lsf0/a;

    .line 154
    .line 155
    invoke-static {v1, p1, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    if-ne p1, v0, :cond_8

    .line 160
    .line 161
    goto :goto_4

    .line 162
    :cond_8
    :goto_3
    check-cast p1, Lyy0/i;

    .line 163
    .line 164
    new-instance v1, Lma0/c;

    .line 165
    .line 166
    const/16 v3, 0x14

    .line 167
    .line 168
    invoke-direct {v1, v5, v3}, Lma0/c;-><init>(Ljava/lang/Object;I)V

    .line 169
    .line 170
    .line 171
    iput v2, p0, Lr60/a;->e:I

    .line 172
    .line 173
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    if-ne p0, v0, :cond_9

    .line 178
    .line 179
    :goto_4
    move-object v6, v0

    .line 180
    :cond_9
    :goto_5
    return-object v6

    .line 181
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 182
    .line 183
    iget v1, p0, Lr60/a;->e:I

    .line 184
    .line 185
    if-eqz v1, :cond_b

    .line 186
    .line 187
    if-ne v1, v7, :cond_a

    .line 188
    .line 189
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    goto :goto_6

    .line 193
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 194
    .line 195
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    throw p0

    .line 199
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    iput v7, p0, Lr60/a;->e:I

    .line 203
    .line 204
    invoke-static {v5, p0}, Lr60/g;->h(Lr60/g;Lrx0/c;)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    if-ne p0, v0, :cond_c

    .line 209
    .line 210
    move-object v6, v0

    .line 211
    :cond_c
    :goto_6
    return-object v6

    .line 212
    nop

    .line 213
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
