.class public final Lyj0/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lyj0/f;

.field public final synthetic g:Lxj0/r;


# direct methods
.method public synthetic constructor <init>(Lyj0/f;Lxj0/r;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lyj0/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyj0/e;->f:Lyj0/f;

    .line 4
    .line 5
    iput-object p2, p0, Lyj0/e;->g:Lxj0/r;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Lyj0/e;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lyj0/e;

    .line 7
    .line 8
    iget-object v0, p0, Lyj0/e;->g:Lxj0/r;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    iget-object p0, p0, Lyj0/e;->f:Lyj0/f;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lyj0/e;-><init>(Lyj0/f;Lxj0/r;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lyj0/e;

    .line 18
    .line 19
    iget-object v0, p0, Lyj0/e;->g:Lxj0/r;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    iget-object p0, p0, Lyj0/e;->f:Lyj0/f;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lyj0/e;-><init>(Lyj0/f;Lxj0/r;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :pswitch_1
    new-instance p1, Lyj0/e;

    .line 29
    .line 30
    iget-object v0, p0, Lyj0/e;->g:Lxj0/r;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    iget-object p0, p0, Lyj0/e;->f:Lyj0/f;

    .line 34
    .line 35
    invoke-direct {p1, p0, v0, p2, v1}, Lyj0/e;-><init>(Lyj0/f;Lxj0/r;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object p1

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
    iget v0, p0, Lyj0/e;->d:I

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
    invoke-virtual {p0, p1, p2}, Lyj0/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lyj0/e;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lyj0/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lyj0/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lyj0/e;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lyj0/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lyj0/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lyj0/e;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lyj0/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lyj0/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lyj0/e;->e:I

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
    goto :goto_1

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
    iget-object p1, p0, Lyj0/e;->f:Lyj0/f;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lyj0/e;->g:Lxj0/r;

    .line 36
    .line 37
    instance-of v3, v1, Lxj0/k;

    .line 38
    .line 39
    if-eqz v3, :cond_2

    .line 40
    .line 41
    check-cast v1, Lxj0/k;

    .line 42
    .line 43
    iget-object v1, v1, Lxj0/k;->j:Ljava/lang/String;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    instance-of v3, v1, Lxj0/m;

    .line 47
    .line 48
    if-eqz v3, :cond_3

    .line 49
    .line 50
    check-cast v1, Lxj0/m;

    .line 51
    .line 52
    iget-object v1, v1, Lxj0/m;->h:Ljava/lang/String;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_3
    instance-of v3, v1, Lxj0/p;

    .line 56
    .line 57
    if-eqz v3, :cond_4

    .line 58
    .line 59
    check-cast v1, Lxj0/p;

    .line 60
    .line 61
    iget-object v1, v1, Lxj0/p;->i:Ljava/lang/String;

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_4
    const/4 v1, 0x0

    .line 65
    :goto_0
    if-eqz v1, :cond_5

    .line 66
    .line 67
    iget-object p1, p1, Lyj0/f;->o:Lck0/d;

    .line 68
    .line 69
    new-instance v3, Ldk0/a;

    .line 70
    .line 71
    sget-object v4, Ldk0/b;->d:Ldk0/b;

    .line 72
    .line 73
    invoke-direct {v3, v1, v4}, Ldk0/a;-><init>(Ljava/lang/String;Ldk0/b;)V

    .line 74
    .line 75
    .line 76
    iput v2, p0, Lyj0/e;->e:I

    .line 77
    .line 78
    invoke-virtual {p1, v3, p0}, Lck0/d;->b(Ldk0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-ne p0, v0, :cond_5

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_5
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    :goto_2
    return-object v0

    .line 88
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 89
    .line 90
    iget v1, p0, Lyj0/e;->e:I

    .line 91
    .line 92
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    const/4 v3, 0x1

    .line 95
    if-eqz v1, :cond_8

    .line 96
    .line 97
    if-ne v1, v3, :cond_7

    .line 98
    .line 99
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    :cond_6
    move-object v0, v2

    .line 103
    goto :goto_3

    .line 104
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 105
    .line 106
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 107
    .line 108
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    iget-object p1, p0, Lyj0/e;->f:Lyj0/f;

    .line 116
    .line 117
    iget-object p1, p1, Lyj0/f;->h:Lwj0/f0;

    .line 118
    .line 119
    iput v3, p0, Lyj0/e;->e:I

    .line 120
    .line 121
    iget-object p0, p0, Lyj0/e;->g:Lxj0/r;

    .line 122
    .line 123
    invoke-virtual {p1, p0}, Lwj0/f0;->c(Lxj0/r;)V

    .line 124
    .line 125
    .line 126
    if-ne v2, v0, :cond_6

    .line 127
    .line 128
    :goto_3
    return-object v0

    .line 129
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 130
    .line 131
    iget v1, p0, Lyj0/e;->e:I

    .line 132
    .line 133
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    const/4 v3, 0x1

    .line 136
    if-eqz v1, :cond_b

    .line 137
    .line 138
    if-ne v1, v3, :cond_a

    .line 139
    .line 140
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    :cond_9
    move-object v0, v2

    .line 144
    goto :goto_4

    .line 145
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 146
    .line 147
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 148
    .line 149
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    throw p0

    .line 153
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    iget-object p1, p0, Lyj0/e;->f:Lyj0/f;

    .line 157
    .line 158
    iget-object p1, p1, Lyj0/f;->h:Lwj0/f0;

    .line 159
    .line 160
    iput v3, p0, Lyj0/e;->e:I

    .line 161
    .line 162
    iget-object p0, p0, Lyj0/e;->g:Lxj0/r;

    .line 163
    .line 164
    invoke-virtual {p1, p0}, Lwj0/f0;->c(Lxj0/r;)V

    .line 165
    .line 166
    .line 167
    if-ne v2, v0, :cond_9

    .line 168
    .line 169
    :goto_4
    return-object v0

    .line 170
    nop

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
