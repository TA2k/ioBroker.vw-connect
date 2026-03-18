.class public final Lsa0/r;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lsa0/s;

.field public final synthetic h:Z


# direct methods
.method public synthetic constructor <init>(Lsa0/s;ZLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lsa0/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsa0/r;->g:Lsa0/s;

    .line 4
    .line 5
    iput-boolean p2, p0, Lsa0/r;->h:Z

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
    iget v0, p0, Lsa0/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lsa0/r;

    .line 7
    .line 8
    iget-boolean v1, p0, Lsa0/r;->h:Z

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Lsa0/r;->g:Lsa0/s;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Lsa0/r;-><init>(Lsa0/s;ZLkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lsa0/r;->f:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lsa0/r;

    .line 20
    .line 21
    iget-boolean v1, p0, Lsa0/r;->h:Z

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iget-object p0, p0, Lsa0/r;->g:Lsa0/s;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Lsa0/r;-><init>(Lsa0/s;ZLkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lsa0/r;->f:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lsa0/r;->d:I

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
    invoke-virtual {p0, p1, p2}, Lsa0/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lsa0/r;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lsa0/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lsa0/r;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lsa0/r;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lsa0/r;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 10

    .line 1
    iget v0, p0, Lsa0/r;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const-string v3, "call to \'resume\' before \'invoke\' with coroutine"

    .line 7
    .line 8
    iget-object v4, p0, Lsa0/r;->g:Lsa0/s;

    .line 9
    .line 10
    iget-boolean v5, p0, Lsa0/r;->h:Z

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lsa0/r;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lvy0/b0;

    .line 19
    .line 20
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    iget v8, p0, Lsa0/r;->e:I

    .line 23
    .line 24
    if-eqz v8, :cond_1

    .line 25
    .line 26
    if-ne v8, v6, :cond_0

    .line 27
    .line 28
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    new-instance p1, Lsa0/q;

    .line 42
    .line 43
    invoke-direct {p1, v4, v5, v6}, Lsa0/q;-><init>(Lsa0/s;ZI)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 47
    .line 48
    .line 49
    iget-object p1, v4, Lsa0/s;->j:Lcs0/d0;

    .line 50
    .line 51
    iput-object v2, p0, Lsa0/r;->f:Ljava/lang/Object;

    .line 52
    .line 53
    iput v6, p0, Lsa0/r;->e:I

    .line 54
    .line 55
    invoke-virtual {p1, v5, p0}, Lcs0/d0;->b(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    if-ne p0, v7, :cond_2

    .line 60
    .line 61
    move-object v1, v7

    .line 62
    :cond_2
    :goto_0
    return-object v1

    .line 63
    :pswitch_0
    iget-object v0, p0, Lsa0/r;->f:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v0, Lvy0/b0;

    .line 66
    .line 67
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 68
    .line 69
    iget v8, p0, Lsa0/r;->e:I

    .line 70
    .line 71
    const/4 v9, 0x2

    .line 72
    if-eqz v8, :cond_5

    .line 73
    .line 74
    if-eq v8, v6, :cond_4

    .line 75
    .line 76
    if-ne v8, v9, :cond_3

    .line 77
    .line 78
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 83
    .line 84
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    new-instance p1, Lsa0/q;

    .line 96
    .line 97
    const/4 v3, 0x0

    .line 98
    invoke-direct {p1, v4, v5, v3}, Lsa0/q;-><init>(Lsa0/s;ZI)V

    .line 99
    .line 100
    .line 101
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 102
    .line 103
    .line 104
    iget-object p1, v4, Lsa0/s;->k:Lkf0/g0;

    .line 105
    .line 106
    new-instance v0, Llf0/b;

    .line 107
    .line 108
    sget-object v3, Lss0/e;->d:Lss0/e;

    .line 109
    .line 110
    invoke-direct {v0, v5}, Llf0/b;-><init>(Z)V

    .line 111
    .line 112
    .line 113
    iput-object v2, p0, Lsa0/r;->f:Ljava/lang/Object;

    .line 114
    .line 115
    iput v6, p0, Lsa0/r;->e:I

    .line 116
    .line 117
    iget-object v3, p1, Lkf0/g0;->a:Lkf0/m;

    .line 118
    .line 119
    invoke-static {v3}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    new-instance v6, Lac/k;

    .line 124
    .line 125
    const/16 v8, 0x14

    .line 126
    .line 127
    invoke-direct {v6, v8, p1, v0, v2}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 128
    .line 129
    .line 130
    invoke-static {v3, v6}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    iget-object p1, p1, Lkf0/g0;->c:Lsf0/a;

    .line 135
    .line 136
    invoke-static {v0, p1, v2}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    if-ne p1, v7, :cond_6

    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_6
    :goto_1
    check-cast p1, Lyy0/i;

    .line 144
    .line 145
    new-instance v0, Lc00/g;

    .line 146
    .line 147
    const/4 v3, 0x3

    .line 148
    invoke-direct {v0, v4, v5, v3}, Lc00/g;-><init>(Ljava/lang/Object;ZI)V

    .line 149
    .line 150
    .line 151
    iput-object v2, p0, Lsa0/r;->f:Ljava/lang/Object;

    .line 152
    .line 153
    iput v9, p0, Lsa0/r;->e:I

    .line 154
    .line 155
    invoke-interface {p1, v0, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-ne p0, v7, :cond_7

    .line 160
    .line 161
    :goto_2
    move-object v1, v7

    .line 162
    :cond_7
    :goto_3
    return-object v1

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
