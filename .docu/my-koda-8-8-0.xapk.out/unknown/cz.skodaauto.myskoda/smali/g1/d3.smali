.class public final Lg1/d3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lvy0/i1;

.field public final synthetic h:Lrx0/i;


# direct methods
.method public constructor <init>(Lvy0/i1;Lay0/n;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lg1/d3;->d:I

    .line 2
    .line 3
    packed-switch p4, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lg1/d3;->g:Lvy0/i1;

    .line 7
    .line 8
    check-cast p2, Lrx0/i;

    .line 9
    .line 10
    iput-object p2, p0, Lg1/d3;->h:Lrx0/i;

    .line 11
    .line 12
    const/4 p1, 0x2

    .line 13
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    iput-object p1, p0, Lg1/d3;->g:Lvy0/i1;

    .line 18
    .line 19
    check-cast p2, Lrx0/i;

    .line 20
    .line 21
    iput-object p2, p0, Lg1/d3;->h:Lrx0/i;

    .line 22
    .line 23
    const/4 p1, 0x2

    .line 24
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lg1/d3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lg1/d3;

    .line 7
    .line 8
    iget-object v1, p0, Lg1/d3;->h:Lrx0/i;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Lg1/d3;->g:Lvy0/i1;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Lg1/d3;-><init>(Lvy0/i1;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lg1/d3;->f:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lg1/d3;

    .line 20
    .line 21
    iget-object v1, p0, Lg1/d3;->h:Lrx0/i;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iget-object p0, p0, Lg1/d3;->g:Lvy0/i1;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Lg1/d3;-><init>(Lvy0/i1;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lg1/d3;->f:Ljava/lang/Object;

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
    iget v0, p0, Lg1/d3;->d:I

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
    invoke-virtual {p0, p1, p2}, Lg1/d3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/d3;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/d3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg1/d3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg1/d3;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg1/d3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 5

    .line 1
    iget v0, p0, Lg1/d3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lg1/d3;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lg1/d3;->e:I

    .line 13
    .line 14
    const/4 v3, 0x2

    .line 15
    const/4 v4, 0x1

    .line 16
    if-eqz v2, :cond_2

    .line 17
    .line 18
    if-eq v2, v4, :cond_1

    .line 19
    .line 20
    if-ne v2, v3, :cond_0

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
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
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p1, p0, Lg1/d3;->g:Lvy0/i1;

    .line 42
    .line 43
    if-eqz p1, :cond_3

    .line 44
    .line 45
    iput-object v0, p0, Lg1/d3;->f:Ljava/lang/Object;

    .line 46
    .line 47
    iput v4, p0, Lg1/d3;->e:I

    .line 48
    .line 49
    invoke-static {p1, p0}, Lvy0/e0;->m(Lvy0/i1;Lrx0/c;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    if-ne p1, v1, :cond_3

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_3
    :goto_0
    invoke-static {v0}, Lvy0/e0;->B(Lvy0/b0;)Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-eqz p1, :cond_4

    .line 61
    .line 62
    const/4 p1, 0x0

    .line 63
    iput-object p1, p0, Lg1/d3;->f:Ljava/lang/Object;

    .line 64
    .line 65
    iput v3, p0, Lg1/d3;->e:I

    .line 66
    .line 67
    iget-object p1, p0, Lg1/d3;->h:Lrx0/i;

    .line 68
    .line 69
    invoke-interface {p1, v0, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    if-ne p0, v1, :cond_4

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_4
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    :goto_2
    return-object v1

    .line 79
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 80
    .line 81
    iget v1, p0, Lg1/d3;->e:I

    .line 82
    .line 83
    const/4 v2, 0x2

    .line 84
    const/4 v3, 0x1

    .line 85
    if-eqz v1, :cond_7

    .line 86
    .line 87
    if-eq v1, v3, :cond_6

    .line 88
    .line 89
    if-ne v1, v2, :cond_5

    .line 90
    .line 91
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 96
    .line 97
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 98
    .line 99
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :cond_6
    iget-object v1, p0, Lg1/d3;->f:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v1, Lvy0/b0;

    .line 106
    .line 107
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    iget-object p1, p0, Lg1/d3;->f:Ljava/lang/Object;

    .line 115
    .line 116
    move-object v1, p1

    .line 117
    check-cast v1, Lvy0/b0;

    .line 118
    .line 119
    iput-object v1, p0, Lg1/d3;->f:Ljava/lang/Object;

    .line 120
    .line 121
    iput v3, p0, Lg1/d3;->e:I

    .line 122
    .line 123
    iget-object p1, p0, Lg1/d3;->g:Lvy0/i1;

    .line 124
    .line 125
    invoke-interface {p1, p0}, Lvy0/i1;->l(Lrx0/c;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    if-ne p1, v0, :cond_8

    .line 130
    .line 131
    goto :goto_5

    .line 132
    :cond_8
    :goto_3
    const/4 p1, 0x0

    .line 133
    iput-object p1, p0, Lg1/d3;->f:Ljava/lang/Object;

    .line 134
    .line 135
    iput v2, p0, Lg1/d3;->e:I

    .line 136
    .line 137
    iget-object p1, p0, Lg1/d3;->h:Lrx0/i;

    .line 138
    .line 139
    invoke-interface {p1, v1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    if-ne p0, v0, :cond_9

    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_9
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 147
    .line 148
    :goto_5
    return-object v0

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
