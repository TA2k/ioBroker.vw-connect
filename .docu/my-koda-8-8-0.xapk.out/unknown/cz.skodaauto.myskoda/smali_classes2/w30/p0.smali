.class public final Lw30/p0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lw30/r0;


# direct methods
.method public synthetic constructor <init>(Lw30/r0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lw30/p0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw30/p0;->f:Lw30/r0;

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
    iget p1, p0, Lw30/p0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lw30/p0;

    .line 7
    .line 8
    iget-object p0, p0, Lw30/p0;->f:Lw30/r0;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lw30/p0;-><init>(Lw30/r0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lw30/p0;

    .line 16
    .line 17
    iget-object p0, p0, Lw30/p0;->f:Lw30/r0;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lw30/p0;-><init>(Lw30/r0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lw30/p0;

    .line 25
    .line 26
    iget-object p0, p0, Lw30/p0;->f:Lw30/r0;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lw30/p0;-><init>(Lw30/r0;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lw30/p0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lw30/p0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lw30/p0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lw30/p0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lw30/p0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lw30/p0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lw30/p0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lw30/p0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lw30/p0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lw30/p0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lw30/p0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lw30/p0;->e:I

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
    iget-object p1, p0, Lw30/p0;->f:Lw30/r0;

    .line 31
    .line 32
    iget-object v1, p1, Lw30/r0;->i:Lu30/j0;

    .line 33
    .line 34
    new-instance v3, Lv30/b;

    .line 35
    .line 36
    sget-object v4, Lv30/c;->f:Lv30/c;

    .line 37
    .line 38
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    check-cast v5, Lw30/q0;

    .line 43
    .line 44
    iget-boolean v5, v5, Lw30/q0;->d:Z

    .line 45
    .line 46
    invoke-direct {v3, v4, v5}, Lv30/b;-><init>(Lv30/c;Z)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1, v3}, Lu30/j0;->a(Lv30/b;)Lyy0/m1;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-static {v1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    new-instance v3, Lw30/o0;

    .line 58
    .line 59
    const/4 v4, 0x1

    .line 60
    invoke-direct {v3, p1, v4}, Lw30/o0;-><init>(Lw30/r0;I)V

    .line 61
    .line 62
    .line 63
    iput v2, p0, Lw30/p0;->e:I

    .line 64
    .line 65
    invoke-virtual {v1, v3, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    if-ne p0, v0, :cond_2

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    :goto_1
    return-object v0

    .line 75
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 76
    .line 77
    iget v1, p0, Lw30/p0;->e:I

    .line 78
    .line 79
    const/4 v2, 0x1

    .line 80
    if-eqz v1, :cond_4

    .line 81
    .line 82
    if-ne v1, v2, :cond_3

    .line 83
    .line 84
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 89
    .line 90
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 91
    .line 92
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget-object p1, p0, Lw30/p0;->f:Lw30/r0;

    .line 100
    .line 101
    iget-object v1, p1, Lw30/r0;->j:Lwr0/i;

    .line 102
    .line 103
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    check-cast v1, Lyy0/i;

    .line 108
    .line 109
    new-instance v3, Ls10/a0;

    .line 110
    .line 111
    const/4 v4, 0x0

    .line 112
    const/16 v5, 0x19

    .line 113
    .line 114
    invoke-direct {v3, p1, v4, v5}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 115
    .line 116
    .line 117
    iput v2, p0, Lw30/p0;->e:I

    .line 118
    .line 119
    invoke-static {v3, p0, v1}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    if-ne p0, v0, :cond_5

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 127
    .line 128
    :goto_3
    return-object v0

    .line 129
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 130
    .line 131
    iget v1, p0, Lw30/p0;->e:I

    .line 132
    .line 133
    const/4 v2, 0x1

    .line 134
    if-eqz v1, :cond_7

    .line 135
    .line 136
    if-ne v1, v2, :cond_6

    .line 137
    .line 138
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_6
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
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    iget-object p1, p0, Lw30/p0;->f:Lw30/r0;

    .line 154
    .line 155
    iget-object v1, p1, Lw30/r0;->h:Lu30/f;

    .line 156
    .line 157
    sget-object v3, Lv30/c;->f:Lv30/c;

    .line 158
    .line 159
    invoke-virtual {v1, v3}, Lu30/f;->a(Lv30/c;)Lyy0/m1;

    .line 160
    .line 161
    .line 162
    move-result-object v1

    .line 163
    invoke-static {v1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    new-instance v3, Lw30/o0;

    .line 168
    .line 169
    const/4 v4, 0x0

    .line 170
    invoke-direct {v3, p1, v4}, Lw30/o0;-><init>(Lw30/r0;I)V

    .line 171
    .line 172
    .line 173
    iput v2, p0, Lw30/p0;->e:I

    .line 174
    .line 175
    invoke-virtual {v1, v3, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    if-ne p0, v0, :cond_8

    .line 180
    .line 181
    goto :goto_5

    .line 182
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 183
    .line 184
    :goto_5
    return-object v0

    .line 185
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
