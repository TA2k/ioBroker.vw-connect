.class public final Lur0/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:Lyy0/j;

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lur0/g;


# direct methods
.method public synthetic constructor <init>(Lur0/g;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lur0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lur0/f;->h:Lur0/g;

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
    .locals 2

    .line 1
    iget v0, p0, Lur0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lur0/f;

    .line 7
    .line 8
    iget-object p0, p0, Lur0/f;->h:Lur0/g;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lur0/f;-><init>(Lur0/g;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lur0/f;->g:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lur0/f;

    .line 18
    .line 19
    iget-object p0, p0, Lur0/f;->h:Lur0/g;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lur0/f;-><init>(Lur0/g;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lur0/f;->g:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lur0/f;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lur0/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lur0/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lur0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lur0/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lur0/f;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lur0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 8

    .line 1
    iget v0, p0, Lur0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lur0/f;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lyy0/j;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lur0/f;->f:I

    .line 13
    .line 14
    const/4 v3, 0x2

    .line 15
    const/4 v4, 0x1

    .line 16
    const/4 v5, 0x0

    .line 17
    if-eqz v2, :cond_2

    .line 18
    .line 19
    if-eq v2, v4, :cond_1

    .line 20
    .line 21
    if-ne v2, v3, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    iget-object v0, p0, Lur0/f;->e:Lyy0/j;

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lur0/f;->h:Lur0/g;

    .line 45
    .line 46
    iget-object p1, p1, Lur0/g;->a:Lti0/a;

    .line 47
    .line 48
    iput-object v5, p0, Lur0/f;->g:Ljava/lang/Object;

    .line 49
    .line 50
    iput-object v0, p0, Lur0/f;->e:Lyy0/j;

    .line 51
    .line 52
    iput v4, p0, Lur0/f;->f:I

    .line 53
    .line 54
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    if-ne p1, v1, :cond_3

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_3
    :goto_0
    check-cast p1, Lur0/h;

    .line 62
    .line 63
    iget-object v2, p1, Lur0/h;->a:Lla/u;

    .line 64
    .line 65
    const-string v4, "user"

    .line 66
    .line 67
    filled-new-array {v4}, [Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    new-instance v6, Lu2/d;

    .line 72
    .line 73
    const/16 v7, 0x15

    .line 74
    .line 75
    invoke-direct {v6, p1, v7}, Lu2/d;-><init>(Ljava/lang/Object;I)V

    .line 76
    .line 77
    .line 78
    const/4 p1, 0x0

    .line 79
    invoke-static {v2, p1, v4, v6}, Ljp/ga;->a(Lla/u;Z[Ljava/lang/String;Lay0/k;)Lna/j;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    iput-object v5, p0, Lur0/f;->g:Ljava/lang/Object;

    .line 84
    .line 85
    iput-object v5, p0, Lur0/f;->e:Lyy0/j;

    .line 86
    .line 87
    iput v3, p0, Lur0/f;->f:I

    .line 88
    .line 89
    invoke-static {v0, p1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    if-ne p0, v1, :cond_4

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_4
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    :goto_2
    return-object v1

    .line 99
    :pswitch_0
    iget-object v0, p0, Lur0/f;->g:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v0, Lyy0/j;

    .line 102
    .line 103
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 104
    .line 105
    iget v2, p0, Lur0/f;->f:I

    .line 106
    .line 107
    const/4 v3, 0x2

    .line 108
    const/4 v4, 0x1

    .line 109
    const/4 v5, 0x0

    .line 110
    if-eqz v2, :cond_7

    .line 111
    .line 112
    if-eq v2, v4, :cond_6

    .line 113
    .line 114
    if-ne v2, v3, :cond_5

    .line 115
    .line 116
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 121
    .line 122
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 123
    .line 124
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p0

    .line 128
    :cond_6
    iget-object v0, p0, Lur0/f;->e:Lyy0/j;

    .line 129
    .line 130
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    goto :goto_3

    .line 134
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    iget-object p1, p0, Lur0/f;->h:Lur0/g;

    .line 138
    .line 139
    iget-object p1, p1, Lur0/g;->a:Lti0/a;

    .line 140
    .line 141
    iput-object v5, p0, Lur0/f;->g:Ljava/lang/Object;

    .line 142
    .line 143
    iput-object v0, p0, Lur0/f;->e:Lyy0/j;

    .line 144
    .line 145
    iput v4, p0, Lur0/f;->f:I

    .line 146
    .line 147
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    if-ne p1, v1, :cond_8

    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_8
    :goto_3
    check-cast p1, Lur0/h;

    .line 155
    .line 156
    iget-object p1, p1, Lur0/h;->a:Lla/u;

    .line 157
    .line 158
    const-string v2, "user"

    .line 159
    .line 160
    filled-new-array {v2}, [Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    new-instance v4, Lu2/d;

    .line 165
    .line 166
    const/16 v6, 0x17

    .line 167
    .line 168
    invoke-direct {v4, v6}, Lu2/d;-><init>(I)V

    .line 169
    .line 170
    .line 171
    const/4 v6, 0x0

    .line 172
    invoke-static {p1, v6, v2, v4}, Ljp/ga;->a(Lla/u;Z[Ljava/lang/String;Lay0/k;)Lna/j;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    iput-object v5, p0, Lur0/f;->g:Ljava/lang/Object;

    .line 177
    .line 178
    iput-object v5, p0, Lur0/f;->e:Lyy0/j;

    .line 179
    .line 180
    iput v3, p0, Lur0/f;->f:I

    .line 181
    .line 182
    invoke-static {v0, p1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    if-ne p0, v1, :cond_9

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_9
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 190
    .line 191
    :goto_5
    return-object v1

    .line 192
    nop

    .line 193
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
