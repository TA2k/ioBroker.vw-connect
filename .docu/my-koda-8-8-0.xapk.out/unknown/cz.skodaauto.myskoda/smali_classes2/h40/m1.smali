.class public final Lh40/m1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh40/p1;


# direct methods
.method public synthetic constructor <init>(Lh40/p1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh40/m1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/m1;->f:Lh40/p1;

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
    iget p1, p0, Lh40/m1;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh40/m1;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/m1;->f:Lh40/p1;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh40/m1;-><init>(Lh40/p1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh40/m1;

    .line 16
    .line 17
    iget-object p0, p0, Lh40/m1;->f:Lh40/p1;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh40/m1;-><init>(Lh40/p1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh40/m1;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh40/m1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh40/m1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh40/m1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh40/m1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh40/m1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh40/m1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lh40/m1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lh40/m1;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object v3, p0, Lh40/m1;->f:Lh40/p1;

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v2, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

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
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    move-object v4, p1

    .line 37
    check-cast v4, Lh40/o1;

    .line 38
    .line 39
    const/4 v9, 0x0

    .line 40
    const/16 v10, 0x1b

    .line 41
    .line 42
    const/4 v5, 0x0

    .line 43
    const/4 v6, 0x0

    .line 44
    const/4 v7, 0x1

    .line 45
    const/4 v8, 0x0

    .line 46
    invoke-static/range {v4 .. v10}, Lh40/o1;->a(Lh40/o1;Lql0/g;ZZZLjava/util/ArrayList;I)Lh40/o1;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-virtual {v3, p1}, Lql0/j;->g(Lql0/h;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, v3, Lh40/p1;->j:Lf40/x;

    .line 54
    .line 55
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    check-cast p1, Lyy0/i;

    .line 60
    .line 61
    iput v2, p0, Lh40/m1;->e:I

    .line 62
    .line 63
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    if-ne p0, v0, :cond_2

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    :goto_0
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    move-object v4, p0

    .line 75
    check-cast v4, Lh40/o1;

    .line 76
    .line 77
    const/4 v9, 0x0

    .line 78
    const/16 v10, 0x1b

    .line 79
    .line 80
    const/4 v5, 0x0

    .line 81
    const/4 v6, 0x0

    .line 82
    const/4 v7, 0x0

    .line 83
    const/4 v8, 0x0

    .line 84
    invoke-static/range {v4 .. v10}, Lh40/o1;->a(Lh40/o1;Lql0/g;ZZZLjava/util/ArrayList;I)Lh40/o1;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-virtual {v3, p0}, Lql0/j;->g(Lql0/h;)V

    .line 89
    .line 90
    .line 91
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    :goto_1
    return-object v0

    .line 94
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 95
    .line 96
    iget v1, p0, Lh40/m1;->e:I

    .line 97
    .line 98
    iget-object v2, p0, Lh40/m1;->f:Lh40/p1;

    .line 99
    .line 100
    const/4 v3, 0x2

    .line 101
    const/4 v4, 0x1

    .line 102
    if-eqz v1, :cond_5

    .line 103
    .line 104
    if-eq v1, v4, :cond_4

    .line 105
    .line 106
    if-ne v1, v3, :cond_3

    .line 107
    .line 108
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 113
    .line 114
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 115
    .line 116
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw p0

    .line 120
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    iget-object p1, v2, Lh40/p1;->i:Lf40/o1;

    .line 128
    .line 129
    iput v4, p0, Lh40/m1;->e:I

    .line 130
    .line 131
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    iget-object v9, p1, Lf40/o1;->a:Lf40/e1;

    .line 135
    .line 136
    move-object v1, v9

    .line 137
    check-cast v1, Ld40/g;

    .line 138
    .line 139
    iget-object v4, v1, Ld40/g;->d:Lyy0/l1;

    .line 140
    .line 141
    iget-object v1, v1, Ld40/g;->b:Lez0/c;

    .line 142
    .line 143
    new-instance v5, La90/r;

    .line 144
    .line 145
    const/4 v6, 0x0

    .line 146
    const/16 v7, 0xb

    .line 147
    .line 148
    const-class v8, Lf40/e1;

    .line 149
    .line 150
    const-string v10, "isDataValid"

    .line 151
    .line 152
    const-string v11, "isDataValid()Z"

    .line 153
    .line 154
    invoke-direct/range {v5 .. v11}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    new-instance v6, Lbq0/i;

    .line 158
    .line 159
    const/4 v7, 0x0

    .line 160
    const/16 v8, 0xe

    .line 161
    .line 162
    invoke-direct {v6, p1, v7, v8}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 163
    .line 164
    .line 165
    invoke-static {v4, v1, v5, v6}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    if-ne p1, v0, :cond_6

    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_6
    :goto_2
    check-cast p1, Lyy0/i;

    .line 173
    .line 174
    new-instance v1, La60/b;

    .line 175
    .line 176
    const/16 v4, 0x16

    .line 177
    .line 178
    invoke-direct {v1, v2, v4}, La60/b;-><init>(Lql0/j;I)V

    .line 179
    .line 180
    .line 181
    iput v3, p0, Lh40/m1;->e:I

    .line 182
    .line 183
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    if-ne p0, v0, :cond_7

    .line 188
    .line 189
    goto :goto_4

    .line 190
    :cond_7
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 191
    .line 192
    :goto_4
    return-object v0

    .line 193
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
