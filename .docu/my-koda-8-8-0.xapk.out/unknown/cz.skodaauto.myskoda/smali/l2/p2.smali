.class public final Ll2/p2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lay0/n;

.field public final synthetic h:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lay0/n;Ll2/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Ll2/p2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ll2/p2;->g:Lay0/n;

    .line 4
    .line 5
    iput-object p2, p0, Ll2/p2;->h:Ll2/b1;

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
    .locals 3

    .line 1
    iget v0, p0, Ll2/p2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ll2/p2;

    .line 7
    .line 8
    iget-object v1, p0, Ll2/p2;->h:Ll2/b1;

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    iget-object p0, p0, Ll2/p2;->g:Lay0/n;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Ll2/p2;-><init>(Lay0/n;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Ll2/p2;->f:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Ll2/p2;

    .line 20
    .line 21
    iget-object v1, p0, Ll2/p2;->h:Ll2/b1;

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    iget-object p0, p0, Ll2/p2;->g:Lay0/n;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Ll2/p2;-><init>(Lay0/n;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Ll2/p2;->f:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_1
    new-instance v0, Ll2/p2;

    .line 33
    .line 34
    iget-object v1, p0, Ll2/p2;->h:Ll2/b1;

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    iget-object p0, p0, Ll2/p2;->g:Lay0/n;

    .line 38
    .line 39
    invoke-direct {v0, p0, v1, p2, v2}, Ll2/p2;-><init>(Lay0/n;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    iput-object p1, v0, Ll2/p2;->f:Ljava/lang/Object;

    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ll2/p2;->d:I

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
    invoke-virtual {p0, p1, p2}, Ll2/p2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ll2/p2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ll2/p2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ll2/p2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ll2/p2;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ll2/p2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ll2/p2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ll2/p2;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ll2/p2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 4

    .line 1
    iget v0, p0, Ll2/p2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ll2/p2;->e:I

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
    iget-object p1, p0, Ll2/p2;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Lvy0/b0;

    .line 33
    .line 34
    new-instance v1, Ll2/r1;

    .line 35
    .line 36
    iget-object v3, p0, Ll2/p2;->h:Ll2/b1;

    .line 37
    .line 38
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-direct {v1, v3, p1}, Ll2/r1;-><init>(Ll2/b1;Lpx0/g;)V

    .line 43
    .line 44
    .line 45
    iput v2, p0, Ll2/p2;->e:I

    .line 46
    .line 47
    iget-object p1, p0, Ll2/p2;->g:Lay0/n;

    .line 48
    .line 49
    invoke-interface {p1, v1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    if-ne p0, v0, :cond_2

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    :goto_1
    return-object v0

    .line 59
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 60
    .line 61
    iget v1, p0, Ll2/p2;->e:I

    .line 62
    .line 63
    const/4 v2, 0x1

    .line 64
    if-eqz v1, :cond_4

    .line 65
    .line 66
    if-ne v1, v2, :cond_3

    .line 67
    .line 68
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 75
    .line 76
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0

    .line 80
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    iget-object p1, p0, Ll2/p2;->f:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p1, Lvy0/b0;

    .line 86
    .line 87
    new-instance v1, Ll2/r1;

    .line 88
    .line 89
    iget-object v3, p0, Ll2/p2;->h:Ll2/b1;

    .line 90
    .line 91
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-direct {v1, v3, p1}, Ll2/r1;-><init>(Ll2/b1;Lpx0/g;)V

    .line 96
    .line 97
    .line 98
    iput v2, p0, Ll2/p2;->e:I

    .line 99
    .line 100
    iget-object p1, p0, Ll2/p2;->g:Lay0/n;

    .line 101
    .line 102
    invoke-interface {p1, v1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    if-ne p0, v0, :cond_5

    .line 107
    .line 108
    goto :goto_3

    .line 109
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    :goto_3
    return-object v0

    .line 112
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 113
    .line 114
    iget v1, p0, Ll2/p2;->e:I

    .line 115
    .line 116
    const/4 v2, 0x1

    .line 117
    if-eqz v1, :cond_7

    .line 118
    .line 119
    if-ne v1, v2, :cond_6

    .line 120
    .line 121
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 126
    .line 127
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 128
    .line 129
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw p0

    .line 133
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iget-object p1, p0, Ll2/p2;->f:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast p1, Lvy0/b0;

    .line 139
    .line 140
    new-instance v1, Ll2/r1;

    .line 141
    .line 142
    iget-object v3, p0, Ll2/p2;->h:Ll2/b1;

    .line 143
    .line 144
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    invoke-direct {v1, v3, p1}, Ll2/r1;-><init>(Ll2/b1;Lpx0/g;)V

    .line 149
    .line 150
    .line 151
    iput v2, p0, Ll2/p2;->e:I

    .line 152
    .line 153
    iget-object p1, p0, Ll2/p2;->g:Lay0/n;

    .line 154
    .line 155
    invoke-interface {p1, v1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-ne p0, v0, :cond_8

    .line 160
    .line 161
    goto :goto_5

    .line 162
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    :goto_5
    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
