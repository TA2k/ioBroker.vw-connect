.class public final Lh40/s1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh40/t1;


# direct methods
.method public synthetic constructor <init>(Lh40/t1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh40/s1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/s1;->f:Lh40/t1;

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
    iget p1, p0, Lh40/s1;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh40/s1;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/s1;->f:Lh40/t1;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh40/s1;-><init>(Lh40/t1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh40/s1;

    .line 16
    .line 17
    iget-object p0, p0, Lh40/s1;->f:Lh40/t1;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh40/s1;-><init>(Lh40/t1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lh40/s1;

    .line 25
    .line 26
    iget-object p0, p0, Lh40/s1;->f:Lh40/t1;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lh40/s1;-><init>(Lh40/t1;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lh40/s1;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh40/s1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh40/s1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh40/s1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh40/s1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh40/s1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh40/s1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lh40/s1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lh40/s1;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lh40/s1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 7

    .line 1
    iget v0, p0, Lh40/s1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lh40/s1;->e:I

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
    iget-object p1, p0, Lh40/s1;->f:Lh40/t1;

    .line 31
    .line 32
    iget-object v1, p1, Lh40/t1;->n:Lf40/t;

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
    new-instance v3, Lh40/r1;

    .line 41
    .line 42
    const/4 v4, 0x1

    .line 43
    invoke-direct {v3, p1, v4}, Lh40/r1;-><init>(Lh40/t1;I)V

    .line 44
    .line 45
    .line 46
    iput v2, p0, Lh40/s1;->e:I

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
    iget v1, p0, Lh40/s1;->e:I

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
    iget-object p1, p0, Lh40/s1;->f:Lh40/t1;

    .line 83
    .line 84
    iget-object v1, p1, Lh40/t1;->l:Lf40/m;

    .line 85
    .line 86
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    new-instance v3, Le1/e;

    .line 90
    .line 91
    const/16 v4, 0xc

    .line 92
    .line 93
    const/4 v5, 0x0

    .line 94
    invoke-direct {v3, v4, v5, v1, v5}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 95
    .line 96
    .line 97
    new-instance v1, Lyy0/m1;

    .line 98
    .line 99
    invoke-direct {v1, v3}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 100
    .line 101
    .line 102
    new-instance v3, La60/b;

    .line 103
    .line 104
    const/16 v4, 0x17

    .line 105
    .line 106
    invoke-direct {v3, p1, v4}, La60/b;-><init>(Lql0/j;I)V

    .line 107
    .line 108
    .line 109
    iput v2, p0, Lh40/s1;->e:I

    .line 110
    .line 111
    invoke-virtual {v1, v3, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    if-ne p0, v0, :cond_5

    .line 116
    .line 117
    goto :goto_3

    .line 118
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    :goto_3
    return-object v0

    .line 121
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 122
    .line 123
    iget v1, p0, Lh40/s1;->e:I

    .line 124
    .line 125
    iget-object v2, p0, Lh40/s1;->f:Lh40/t1;

    .line 126
    .line 127
    const/4 v3, 0x2

    .line 128
    const/4 v4, 0x1

    .line 129
    if-eqz v1, :cond_8

    .line 130
    .line 131
    if-eq v1, v4, :cond_7

    .line 132
    .line 133
    if-ne v1, v3, :cond_6

    .line 134
    .line 135
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    goto :goto_5

    .line 139
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 140
    .line 141
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 142
    .line 143
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    throw p0

    .line 147
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    goto :goto_4

    .line 151
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    iget-object p1, v2, Lh40/t1;->r:Lf40/q4;

    .line 155
    .line 156
    iput v4, p0, Lh40/s1;->e:I

    .line 157
    .line 158
    iget-object p1, p1, Lf40/q4;->a:Lce0/d;

    .line 159
    .line 160
    iget-object v1, p1, Lce0/d;->a:Lxl0/f;

    .line 161
    .line 162
    new-instance v4, Lce0/c;

    .line 163
    .line 164
    const/4 v5, 0x0

    .line 165
    const/4 v6, 0x1

    .line 166
    invoke-direct {v4, p1, v5, v6}, Lce0/c;-><init>(Lce0/d;Lkotlin/coroutines/Continuation;I)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v1, v4}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    if-ne p1, v0, :cond_9

    .line 174
    .line 175
    goto :goto_6

    .line 176
    :cond_9
    :goto_4
    check-cast p1, Lyy0/i;

    .line 177
    .line 178
    new-instance v1, Lh40/r1;

    .line 179
    .line 180
    const/4 v4, 0x0

    .line 181
    invoke-direct {v1, v2, v4}, Lh40/r1;-><init>(Lh40/t1;I)V

    .line 182
    .line 183
    .line 184
    iput v3, p0, Lh40/s1;->e:I

    .line 185
    .line 186
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    if-ne p0, v0, :cond_a

    .line 191
    .line 192
    goto :goto_6

    .line 193
    :cond_a
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 194
    .line 195
    :goto_6
    return-object v0

    .line 196
    nop

    .line 197
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
