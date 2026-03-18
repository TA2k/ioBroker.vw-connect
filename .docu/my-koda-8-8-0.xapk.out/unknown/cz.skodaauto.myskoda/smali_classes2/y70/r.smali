.class public final Ly70/r;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ly70/e0;


# direct methods
.method public synthetic constructor <init>(Ly70/e0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly70/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/r;->f:Ly70/e0;

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
    iget p1, p0, Ly70/r;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ly70/r;

    .line 7
    .line 8
    iget-object p0, p0, Ly70/r;->f:Ly70/e0;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ly70/r;-><init>(Ly70/e0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ly70/r;

    .line 16
    .line 17
    iget-object p0, p0, Ly70/r;->f:Ly70/e0;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ly70/r;-><init>(Ly70/e0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ly70/r;

    .line 25
    .line 26
    iget-object p0, p0, Ly70/r;->f:Ly70/e0;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ly70/r;-><init>(Ly70/e0;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ly70/r;->d:I

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
    invoke-virtual {p0, p1, p2}, Ly70/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly70/r;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly70/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly70/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ly70/r;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ly70/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ly70/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ly70/r;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ly70/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Ly70/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ly70/r;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object v3, p0, Ly70/r;->f:Ly70/e0;

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
    iget-object p1, v3, Ly70/e0;->n:Ltn0/b;

    .line 33
    .line 34
    sget-object v1, Lun0/a;->e:Lun0/a;

    .line 35
    .line 36
    iput v2, p0, Ly70/r;->e:I

    .line 37
    .line 38
    invoke-virtual {p1, v1, p0}, Ltn0/b;->b(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    if-ne p1, v0, :cond_2

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_2
    :goto_0
    check-cast p1, Lun0/b;

    .line 46
    .line 47
    iget-boolean p0, p1, Lun0/b;->b:Z

    .line 48
    .line 49
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    move-object v4, p1

    .line 54
    check-cast v4, Ly70/z;

    .line 55
    .line 56
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 57
    .line 58
    .line 59
    move-result-object v7

    .line 60
    const/4 v12, 0x0

    .line 61
    const/16 v13, 0xfb

    .line 62
    .line 63
    const/4 v5, 0x0

    .line 64
    const/4 v6, 0x0

    .line 65
    const/4 v8, 0x0

    .line 66
    const/4 v9, 0x0

    .line 67
    const/4 v10, 0x0

    .line 68
    const/4 v11, 0x0

    .line 69
    invoke-static/range {v4 .. v13}, Ly70/z;->a(Ly70/z;Ljava/lang/String;ZLjava/lang/Boolean;Ljava/util/List;Lql0/g;Lql0/g;ZZI)Ly70/z;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-virtual {v3, p1}, Lql0/j;->g(Lql0/h;)V

    .line 74
    .line 75
    .line 76
    if-eqz p0, :cond_3

    .line 77
    .line 78
    iget-object p0, v3, Ly70/e0;->v:Lfg0/a;

    .line 79
    .line 80
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    :cond_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    :goto_1
    return-object v0

    .line 86
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 87
    .line 88
    iget v1, p0, Ly70/r;->e:I

    .line 89
    .line 90
    const/4 v2, 0x1

    .line 91
    if-eqz v1, :cond_5

    .line 92
    .line 93
    if-ne v1, v2, :cond_4

    .line 94
    .line 95
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 100
    .line 101
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 102
    .line 103
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iget-object p1, p0, Ly70/r;->f:Ly70/e0;

    .line 111
    .line 112
    iget-object v1, p1, Ly70/e0;->r:Lwr0/i;

    .line 113
    .line 114
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    check-cast v1, Lyy0/i;

    .line 119
    .line 120
    new-instance v3, Ly70/q;

    .line 121
    .line 122
    const/4 v4, 0x1

    .line 123
    invoke-direct {v3, p1, v4}, Ly70/q;-><init>(Ly70/e0;I)V

    .line 124
    .line 125
    .line 126
    iput v2, p0, Ly70/r;->e:I

    .line 127
    .line 128
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    if-ne p0, v0, :cond_6

    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_6
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    :goto_3
    return-object v0

    .line 138
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 139
    .line 140
    iget v1, p0, Ly70/r;->e:I

    .line 141
    .line 142
    const/4 v2, 0x1

    .line 143
    if-eqz v1, :cond_8

    .line 144
    .line 145
    if-ne v1, v2, :cond_7

    .line 146
    .line 147
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    goto :goto_4

    .line 151
    :cond_7
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
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    iget-object p1, p0, Ly70/r;->f:Ly70/e0;

    .line 163
    .line 164
    iget-object v1, p1, Ly70/e0;->m:Lfg0/d;

    .line 165
    .line 166
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    check-cast v1, Lyy0/i;

    .line 171
    .line 172
    new-instance v3, Ly70/q;

    .line 173
    .line 174
    const/4 v4, 0x0

    .line 175
    invoke-direct {v3, p1, v4}, Ly70/q;-><init>(Ly70/e0;I)V

    .line 176
    .line 177
    .line 178
    iput v2, p0, Ly70/r;->e:I

    .line 179
    .line 180
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    if-ne p0, v0, :cond_9

    .line 185
    .line 186
    goto :goto_5

    .line 187
    :cond_9
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 188
    .line 189
    :goto_5
    return-object v0

    .line 190
    nop

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
