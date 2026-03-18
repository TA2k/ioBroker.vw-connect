.class public final Lr30/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lq30/g;

.field public final synthetic g:Le1/n1;


# direct methods
.method public constructor <init>(Le1/n1;Lq30/g;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lr30/g;->d:I

    .line 1
    iput-object p1, p0, Lr30/g;->g:Le1/n1;

    iput-object p2, p0, Lr30/g;->f:Lq30/g;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lq30/g;Le1/n1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lr30/g;->d:I

    .line 2
    iput-object p1, p0, Lr30/g;->f:Lq30/g;

    iput-object p2, p0, Lr30/g;->g:Le1/n1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lr30/g;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lr30/g;

    .line 7
    .line 8
    iget-object v0, p0, Lr30/g;->f:Lq30/g;

    .line 9
    .line 10
    iget-object p0, p0, Lr30/g;->g:Le1/n1;

    .line 11
    .line 12
    invoke-direct {p1, v0, p0, p2}, Lr30/g;-><init>(Lq30/g;Le1/n1;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_0
    new-instance p1, Lr30/g;

    .line 17
    .line 18
    iget-object v0, p0, Lr30/g;->g:Le1/n1;

    .line 19
    .line 20
    iget-object p0, p0, Lr30/g;->f:Lq30/g;

    .line 21
    .line 22
    invoke-direct {p1, v0, p0, p2}, Lr30/g;-><init>(Le1/n1;Lq30/g;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    return-object p1

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lr30/g;->d:I

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
    invoke-virtual {p0, p1, p2}, Lr30/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lr30/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lr30/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lr30/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lr30/g;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lr30/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lr30/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lr30/g;->e:I

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    if-eq v1, v3, :cond_1

    .line 15
    .line 16
    if-ne v1, v2, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    new-instance p1, Ldj/a;

    .line 38
    .line 39
    const/16 v1, 0xf

    .line 40
    .line 41
    invoke-direct {p1, v1}, Ldj/a;-><init>(I)V

    .line 42
    .line 43
    .line 44
    iput v3, p0, Lr30/g;->e:I

    .line 45
    .line 46
    invoke-interface {p0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    invoke-static {v1}, Ll2/b;->k(Lpx0/g;)Ll2/y0;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    invoke-interface {v1, p1, p0}, Ll2/y0;->q(Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    if-ne p1, v0, :cond_3

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_3
    :goto_0
    iget-object p1, p0, Lr30/g;->f:Lq30/g;

    .line 62
    .line 63
    iget-object p1, p1, Lq30/g;->d:Ljava/util/List;

    .line 64
    .line 65
    check-cast p1, Ljava/util/Collection;

    .line 66
    .line 67
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-nez p1, :cond_4

    .line 72
    .line 73
    iget-object p1, p0, Lr30/g;->g:Le1/n1;

    .line 74
    .line 75
    iget-object v1, p1, Le1/n1;->d:Ll2/g1;

    .line 76
    .line 77
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    iput v2, p0, Lr30/g;->e:I

    .line 82
    .line 83
    invoke-static {p1, v1, p0}, Le1/n1;->f(Le1/n1;ILkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    if-ne p0, v0, :cond_4

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_4
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    :goto_2
    return-object v0

    .line 93
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 94
    .line 95
    iget v1, p0, Lr30/g;->e:I

    .line 96
    .line 97
    const/4 v2, 0x1

    .line 98
    if-eqz v1, :cond_6

    .line 99
    .line 100
    if-ne v1, v2, :cond_5

    .line 101
    .line 102
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 107
    .line 108
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 109
    .line 110
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw p0

    .line 114
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    new-instance p1, Le1/m1;

    .line 118
    .line 119
    const/4 v1, 0x2

    .line 120
    iget-object v3, p0, Lr30/g;->g:Le1/n1;

    .line 121
    .line 122
    invoke-direct {p1, v3, v1}, Le1/m1;-><init>(Le1/n1;I)V

    .line 123
    .line 124
    .line 125
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    new-instance v1, Lqg/l;

    .line 130
    .line 131
    iget-object v4, p0, Lr30/g;->f:Lq30/g;

    .line 132
    .line 133
    const/4 v5, 0x2

    .line 134
    invoke-direct {v1, v5, v4, v3}, Lqg/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    iput v2, p0, Lr30/g;->e:I

    .line 138
    .line 139
    invoke-virtual {p1, v1, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    if-ne p0, v0, :cond_7

    .line 144
    .line 145
    goto :goto_4

    .line 146
    :cond_7
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 147
    .line 148
    :goto_4
    return-object v0

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
