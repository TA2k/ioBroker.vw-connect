.class public final Lhz/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lhz/d;


# direct methods
.method public synthetic constructor <init>(Lhz/d;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhz/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhz/c;->g:Lhz/d;

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
    iget v0, p0, Lhz/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lhz/c;

    .line 7
    .line 8
    iget-object p0, p0, Lhz/c;->g:Lhz/d;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lhz/c;-><init>(Lhz/d;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lhz/c;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lhz/c;

    .line 18
    .line 19
    iget-object p0, p0, Lhz/c;->g:Lhz/d;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lhz/c;-><init>(Lhz/d;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lhz/c;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lhz/c;

    .line 29
    .line 30
    iget-object p0, p0, Lhz/c;->g:Lhz/d;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-direct {v0, p0, p2, v1}, Lhz/c;-><init>(Lhz/d;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lhz/c;->f:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

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
    iget v0, p0, Lhz/c;->d:I

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
    invoke-virtual {p0, p1, p2}, Lhz/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lhz/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lhz/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lhz/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lhz/c;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lhz/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lhz/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lhz/c;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lhz/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 5

    .line 1
    iget v0, p0, Lhz/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lhz/c;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lhz/c;->e:I

    .line 13
    .line 14
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    const/4 v4, 0x1

    .line 17
    if-eqz v2, :cond_2

    .line 18
    .line 19
    if-ne v2, v4, :cond_1

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    move-object v1, v3

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    new-instance p1, Lhz/a;

    .line 38
    .line 39
    const/4 v2, 0x3

    .line 40
    invoke-direct {p1, v2}, Lhz/a;-><init>(I)V

    .line 41
    .line 42
    .line 43
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 44
    .line 45
    .line 46
    iget-object p1, p0, Lhz/c;->g:Lhz/d;

    .line 47
    .line 48
    iget-object p1, p1, Lhz/d;->i:Lfz/b0;

    .line 49
    .line 50
    const/4 v0, 0x0

    .line 51
    iput-object v0, p0, Lhz/c;->f:Ljava/lang/Object;

    .line 52
    .line 53
    iput v4, p0, Lhz/c;->e:I

    .line 54
    .line 55
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1, p0}, Lfz/b0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    if-ne p0, v1, :cond_0

    .line 63
    .line 64
    :goto_0
    return-object v1

    .line 65
    :pswitch_0
    iget-object v0, p0, Lhz/c;->f:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v0, Lvy0/b0;

    .line 68
    .line 69
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 70
    .line 71
    iget v2, p0, Lhz/c;->e:I

    .line 72
    .line 73
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    const/4 v4, 0x1

    .line 76
    if-eqz v2, :cond_5

    .line 77
    .line 78
    if-ne v2, v4, :cond_4

    .line 79
    .line 80
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    :cond_3
    move-object v1, v3

    .line 84
    goto :goto_1

    .line 85
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    new-instance p1, Lhz/a;

    .line 97
    .line 98
    const/4 v2, 0x2

    .line 99
    invoke-direct {p1, v2}, Lhz/a;-><init>(I)V

    .line 100
    .line 101
    .line 102
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 103
    .line 104
    .line 105
    iget-object p1, p0, Lhz/c;->g:Lhz/d;

    .line 106
    .line 107
    iget-object p1, p1, Lhz/d;->h:Lfz/x;

    .line 108
    .line 109
    const/4 v0, 0x0

    .line 110
    iput-object v0, p0, Lhz/c;->f:Ljava/lang/Object;

    .line 111
    .line 112
    iput v4, p0, Lhz/c;->e:I

    .line 113
    .line 114
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    invoke-virtual {p1, p0}, Lfz/x;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    if-ne p0, v1, :cond_3

    .line 122
    .line 123
    :goto_1
    return-object v1

    .line 124
    :pswitch_1
    iget-object v0, p0, Lhz/c;->f:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v0, Lvy0/b0;

    .line 127
    .line 128
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 129
    .line 130
    iget v2, p0, Lhz/c;->e:I

    .line 131
    .line 132
    iget-object v3, p0, Lhz/c;->g:Lhz/d;

    .line 133
    .line 134
    const/4 v4, 0x1

    .line 135
    if-eqz v2, :cond_7

    .line 136
    .line 137
    if-ne v2, v4, :cond_6

    .line 138
    .line 139
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 144
    .line 145
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 146
    .line 147
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    throw p0

    .line 151
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    new-instance p1, Lhz/a;

    .line 155
    .line 156
    const/4 v2, 0x1

    .line 157
    invoke-direct {p1, v2}, Lhz/a;-><init>(I)V

    .line 158
    .line 159
    .line 160
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 161
    .line 162
    .line 163
    iget-object p1, v3, Lhz/d;->j:Lfz/z;

    .line 164
    .line 165
    const/4 v0, 0x0

    .line 166
    iput-object v0, p0, Lhz/c;->f:Ljava/lang/Object;

    .line 167
    .line 168
    iput v4, p0, Lhz/c;->e:I

    .line 169
    .line 170
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 171
    .line 172
    .line 173
    invoke-virtual {p1, p0}, Lfz/z;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    if-ne p0, v1, :cond_8

    .line 178
    .line 179
    goto :goto_3

    .line 180
    :cond_8
    :goto_2
    iget-object p0, v3, Lhz/d;->k:Lfz/v;

    .line 181
    .line 182
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 186
    .line 187
    :goto_3
    return-object v1

    .line 188
    nop

    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
