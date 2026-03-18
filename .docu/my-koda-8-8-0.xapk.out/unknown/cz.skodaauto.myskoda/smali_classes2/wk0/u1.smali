.class public final Lwk0/u1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lwk0/z1;


# direct methods
.method public synthetic constructor <init>(Lwk0/z1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lwk0/u1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lwk0/u1;->f:Lwk0/z1;

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
    iget p1, p0, Lwk0/u1;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lwk0/u1;

    .line 7
    .line 8
    iget-object p0, p0, Lwk0/u1;->f:Lwk0/z1;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lwk0/u1;-><init>(Lwk0/z1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lwk0/u1;

    .line 16
    .line 17
    iget-object p0, p0, Lwk0/u1;->f:Lwk0/z1;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lwk0/u1;-><init>(Lwk0/z1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lwk0/u1;->d:I

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
    invoke-virtual {p0, p1, p2}, Lwk0/u1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lwk0/u1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lwk0/u1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lwk0/u1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lwk0/u1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lwk0/u1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lwk0/u1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lwk0/u1;->e:I

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
    iget-object p1, p0, Lwk0/u1;->f:Lwk0/z1;

    .line 31
    .line 32
    iget-object v1, p1, Lwk0/z1;->i:Luk0/b0;

    .line 33
    .line 34
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Lyy0/i;

    .line 39
    .line 40
    new-instance v3, Llb0/y;

    .line 41
    .line 42
    const/16 v4, 0x11

    .line 43
    .line 44
    invoke-direct {v3, v4, v1, p1}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    new-instance v1, Lam0/i;

    .line 48
    .line 49
    const/16 v4, 0x1a

    .line 50
    .line 51
    invoke-direct {v1, v3, v4}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    new-instance v3, Ltr0/e;

    .line 55
    .line 56
    const/4 v4, 0x0

    .line 57
    const/16 v5, 0x1b

    .line 58
    .line 59
    invoke-direct {v3, p1, v4, v5}, Ltr0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 60
    .line 61
    .line 62
    iput v2, p0, Lwk0/u1;->e:I

    .line 63
    .line 64
    invoke-static {v3, p0, v1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-ne p0, v0, :cond_2

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    :goto_1
    return-object v0

    .line 74
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 75
    .line 76
    iget v1, p0, Lwk0/u1;->e:I

    .line 77
    .line 78
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    const/4 v3, 0x1

    .line 81
    if-eqz v1, :cond_5

    .line 82
    .line 83
    if-ne v1, v3, :cond_4

    .line 84
    .line 85
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_3
    move-object v0, v2

    .line 89
    goto :goto_3

    .line 90
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 91
    .line 92
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 93
    .line 94
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p0

    .line 98
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    iget-object p1, p0, Lwk0/u1;->f:Lwk0/z1;

    .line 102
    .line 103
    iget-object v1, p1, Lwk0/z1;->h:Luk0/c0;

    .line 104
    .line 105
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    check-cast v1, Lyy0/i;

    .line 110
    .line 111
    new-instance v4, Ls90/a;

    .line 112
    .line 113
    const/16 v5, 0x18

    .line 114
    .line 115
    invoke-direct {v4, p1, v5}, Ls90/a;-><init>(Ljava/lang/Object;I)V

    .line 116
    .line 117
    .line 118
    iput v3, p0, Lwk0/u1;->e:I

    .line 119
    .line 120
    new-instance p1, Lwk0/o0;

    .line 121
    .line 122
    const/4 v3, 0x2

    .line 123
    invoke-direct {p1, v4, v3}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 124
    .line 125
    .line 126
    invoke-interface {v1, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    if-ne p0, v0, :cond_6

    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_6
    move-object p0, v2

    .line 134
    :goto_2
    if-ne p0, v0, :cond_3

    .line 135
    .line 136
    :goto_3
    return-object v0

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
