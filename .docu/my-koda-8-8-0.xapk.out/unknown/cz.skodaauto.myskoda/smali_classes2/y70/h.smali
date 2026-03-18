.class public final Ly70/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ly70/o;


# direct methods
.method public synthetic constructor <init>(Ly70/o;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly70/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/h;->f:Ly70/o;

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
    iget p1, p0, Ly70/h;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ly70/h;

    .line 7
    .line 8
    iget-object p0, p0, Ly70/h;->f:Ly70/o;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ly70/h;-><init>(Ly70/o;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ly70/h;

    .line 16
    .line 17
    iget-object p0, p0, Ly70/h;->f:Ly70/o;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ly70/h;-><init>(Ly70/o;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ly70/h;

    .line 25
    .line 26
    iget-object p0, p0, Ly70/h;->f:Ly70/o;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ly70/h;-><init>(Ly70/o;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ly70/h;->d:I

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
    invoke-virtual {p0, p1, p2}, Ly70/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly70/h;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly70/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ly70/h;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ly70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ly70/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ly70/h;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ly70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Ly70/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ly70/h;->e:I

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
    iget-object p1, p0, Ly70/h;->f:Ly70/o;

    .line 31
    .line 32
    iget-object v1, p1, Ly70/o;->p:Lwr0/i;

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
    new-instance v3, Ly70/j;

    .line 41
    .line 42
    const/4 v4, 0x0

    .line 43
    invoke-direct {v3, p1, v4}, Ly70/j;-><init>(Ly70/o;I)V

    .line 44
    .line 45
    .line 46
    iput v2, p0, Ly70/h;->e:I

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
    iget v1, p0, Ly70/h;->e:I

    .line 61
    .line 62
    iget-object v2, p0, Ly70/h;->f:Ly70/o;

    .line 63
    .line 64
    const/4 v3, 0x2

    .line 65
    const/4 v4, 0x1

    .line 66
    if-eqz v1, :cond_5

    .line 67
    .line 68
    if-eq v1, v4, :cond_4

    .line 69
    .line 70
    if-ne v1, v3, :cond_3

    .line 71
    .line 72
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 77
    .line 78
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    iget-object p1, v2, Ly70/o;->l:Lbq0/o;

    .line 92
    .line 93
    iput v4, p0, Ly70/h;->e:I

    .line 94
    .line 95
    iget-object v1, p1, Lbq0/o;->b:Lkf0/o;

    .line 96
    .line 97
    invoke-static {v1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    new-instance v4, La90/c;

    .line 102
    .line 103
    const/4 v5, 0x0

    .line 104
    const/16 v6, 0x8

    .line 105
    .line 106
    invoke-direct {v4, v5, p1, v6}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 107
    .line 108
    .line 109
    invoke-static {v1, v4}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    if-ne p1, v0, :cond_6

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_6
    :goto_2
    check-cast p1, Lyy0/i;

    .line 117
    .line 118
    new-instance v1, Ly70/i;

    .line 119
    .line 120
    const/4 v4, 0x0

    .line 121
    invoke-direct {v1, v2, v4}, Ly70/i;-><init>(Ly70/o;I)V

    .line 122
    .line 123
    .line 124
    iput v3, p0, Ly70/h;->e:I

    .line 125
    .line 126
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    if-ne p0, v0, :cond_7

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_7
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    :goto_4
    return-object v0

    .line 136
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 137
    .line 138
    iget v1, p0, Ly70/h;->e:I

    .line 139
    .line 140
    iget-object v2, p0, Ly70/h;->f:Ly70/o;

    .line 141
    .line 142
    const/4 v3, 0x1

    .line 143
    if-eqz v1, :cond_9

    .line 144
    .line 145
    if-ne v1, v3, :cond_8

    .line 146
    .line 147
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    goto :goto_5

    .line 151
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 152
    .line 153
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 154
    .line 155
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    throw p0

    .line 159
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    iget-object p1, v2, Ly70/o;->t:Lkf0/k;

    .line 163
    .line 164
    iput v3, p0, Ly70/h;->e:I

    .line 165
    .line 166
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 167
    .line 168
    .line 169
    invoke-virtual {p1, p0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    if-ne p1, v0, :cond_a

    .line 174
    .line 175
    goto :goto_6

    .line 176
    :cond_a
    :goto_5
    check-cast p1, Lss0/b;

    .line 177
    .line 178
    sget-object p0, Lss0/e;->e:Lss0/e;

    .line 179
    .line 180
    invoke-static {p1, p0}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 181
    .line 182
    .line 183
    move-result v5

    .line 184
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    move-object v3, p0

    .line 189
    check-cast v3, Ly70/k;

    .line 190
    .line 191
    const/4 v10, 0x0

    .line 192
    const/16 v11, 0x7d

    .line 193
    .line 194
    const/4 v4, 0x0

    .line 195
    const/4 v6, 0x0

    .line 196
    const/4 v7, 0x0

    .line 197
    const/4 v8, 0x0

    .line 198
    const/4 v9, 0x0

    .line 199
    invoke-static/range {v3 .. v11}, Ly70/k;->a(Ly70/k;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ly70/w1;I)Ly70/k;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 204
    .line 205
    .line 206
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 207
    .line 208
    :goto_6
    return-object v0

    .line 209
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
