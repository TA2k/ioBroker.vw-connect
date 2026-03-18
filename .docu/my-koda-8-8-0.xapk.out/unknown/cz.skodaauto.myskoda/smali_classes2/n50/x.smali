.class public final Ln50/x;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ln50/k0;


# direct methods
.method public synthetic constructor <init>(Ln50/k0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ln50/x;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln50/x;->f:Ln50/k0;

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
    iget p1, p0, Ln50/x;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ln50/x;

    .line 7
    .line 8
    iget-object p0, p0, Ln50/x;->f:Ln50/k0;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ln50/x;-><init>(Ln50/k0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ln50/x;

    .line 16
    .line 17
    iget-object p0, p0, Ln50/x;->f:Ln50/k0;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ln50/x;-><init>(Ln50/k0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ln50/x;

    .line 25
    .line 26
    iget-object p0, p0, Ln50/x;->f:Ln50/k0;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ln50/x;-><init>(Ln50/k0;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ln50/x;->d:I

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
    invoke-virtual {p0, p1, p2}, Ln50/x;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ln50/x;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ln50/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ln50/x;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ln50/x;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ln50/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ln50/x;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ln50/x;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ln50/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 9

    .line 1
    iget v0, p0, Ln50/x;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v4, p0, Ln50/x;->f:Ln50/k0;

    .line 8
    .line 9
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 10
    .line 11
    const/4 v6, 0x1

    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    iget v7, p0, Ln50/x;->e:I

    .line 18
    .line 19
    if-eqz v7, :cond_1

    .line 20
    .line 21
    if-ne v7, v6, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, v4, Ln50/k0;->o:Lrq0/f;

    .line 37
    .line 38
    new-instance v4, Lsq0/c;

    .line 39
    .line 40
    const v5, 0x7f1206f1

    .line 41
    .line 42
    .line 43
    const/4 v7, 0x6

    .line 44
    invoke-direct {v4, v5, v7, v2}, Lsq0/c;-><init>(IILjava/lang/Integer;)V

    .line 45
    .line 46
    .line 47
    iput v6, p0, Ln50/x;->e:I

    .line 48
    .line 49
    invoke-virtual {p1, v4, v1, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    if-ne p0, v0, :cond_2

    .line 54
    .line 55
    move-object v3, v0

    .line 56
    :cond_2
    :goto_0
    return-object v3

    .line 57
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 58
    .line 59
    iget v1, p0, Ln50/x;->e:I

    .line 60
    .line 61
    if-eqz v1, :cond_4

    .line 62
    .line 63
    if-ne v1, v6, :cond_3

    .line 64
    .line 65
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw p0

    .line 75
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    iget-object p1, v4, Ln50/k0;->t:Lal0/v0;

    .line 79
    .line 80
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    check-cast p1, Lyy0/i;

    .line 85
    .line 86
    new-instance v1, Lma0/c;

    .line 87
    .line 88
    const/4 v2, 0x5

    .line 89
    invoke-direct {v1, v4, v2}, Lma0/c;-><init>(Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    iput v6, p0, Ln50/x;->e:I

    .line 93
    .line 94
    new-instance v2, Lkf0/x;

    .line 95
    .line 96
    const/16 v4, 0x1a

    .line 97
    .line 98
    invoke-direct {v2, v1, v4}, Lkf0/x;-><init>(Lyy0/j;I)V

    .line 99
    .line 100
    .line 101
    invoke-interface {p1, v2, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-ne p0, v0, :cond_5

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_5
    move-object p0, v3

    .line 109
    :goto_1
    if-ne p0, v0, :cond_6

    .line 110
    .line 111
    move-object v3, v0

    .line 112
    :cond_6
    :goto_2
    return-object v3

    .line 113
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 114
    .line 115
    iget v7, p0, Ln50/x;->e:I

    .line 116
    .line 117
    if-eqz v7, :cond_8

    .line 118
    .line 119
    if-ne v7, v6, :cond_7

    .line 120
    .line 121
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    goto :goto_5

    .line 125
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 126
    .line 127
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw p0

    .line 131
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    iget-object p1, v4, Ln50/k0;->k:Lal0/u0;

    .line 135
    .line 136
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    check-cast p1, Lyy0/i;

    .line 141
    .line 142
    invoke-static {p1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    iget-object v5, v4, Ln50/k0;->l:Lal0/w0;

    .line 147
    .line 148
    invoke-static {v5}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v5

    .line 152
    check-cast v5, Lyy0/i;

    .line 153
    .line 154
    new-instance v7, Lgb0/z;

    .line 155
    .line 156
    const/16 v8, 0x17

    .line 157
    .line 158
    invoke-direct {v7, v4, v2, v8}, Lgb0/z;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 159
    .line 160
    .line 161
    iput v6, p0, Ln50/x;->e:I

    .line 162
    .line 163
    const/4 v4, 0x2

    .line 164
    new-array v4, v4, [Lyy0/i;

    .line 165
    .line 166
    aput-object p1, v4, v1

    .line 167
    .line 168
    aput-object v5, v4, v6

    .line 169
    .line 170
    new-instance p1, Lyy0/g1;

    .line 171
    .line 172
    invoke-direct {p1, v7, v2}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 173
    .line 174
    .line 175
    sget-object v1, Lyy0/h1;->d:Lyy0/h1;

    .line 176
    .line 177
    sget-object v2, Lzy0/q;->d:Lzy0/q;

    .line 178
    .line 179
    invoke-static {v1, p1, p0, v2, v4}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 184
    .line 185
    if-ne p0, p1, :cond_9

    .line 186
    .line 187
    goto :goto_3

    .line 188
    :cond_9
    move-object p0, v3

    .line 189
    :goto_3
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 190
    .line 191
    if-ne p0, p1, :cond_a

    .line 192
    .line 193
    goto :goto_4

    .line 194
    :cond_a
    move-object p0, v3

    .line 195
    :goto_4
    if-ne p0, v0, :cond_b

    .line 196
    .line 197
    move-object v3, v0

    .line 198
    :cond_b
    :goto_5
    return-object v3

    .line 199
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
