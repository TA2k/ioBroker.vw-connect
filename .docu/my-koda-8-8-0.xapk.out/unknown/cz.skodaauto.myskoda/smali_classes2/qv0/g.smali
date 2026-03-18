.class public final Lqv0/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lm1/t;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lm1/t;Ll2/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lqv0/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqv0/g;->f:Lm1/t;

    .line 4
    .line 5
    iput-object p2, p0, Lqv0/g;->g:Ll2/b1;

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
    iget p1, p0, Lqv0/g;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lqv0/g;

    .line 7
    .line 8
    iget-object v0, p0, Lqv0/g;->g:Ll2/b1;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lqv0/g;->f:Lm1/t;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lqv0/g;-><init>(Lm1/t;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lqv0/g;

    .line 18
    .line 19
    iget-object v0, p0, Lqv0/g;->g:Ll2/b1;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lqv0/g;->f:Lm1/t;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lqv0/g;-><init>(Lm1/t;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

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
    iget v0, p0, Lqv0/g;->d:I

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
    invoke-virtual {p0, p1, p2}, Lqv0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lqv0/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lqv0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lqv0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lqv0/g;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lqv0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lqv0/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lqv0/g;->e:I

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
    new-instance p1, Lh2/t2;

    .line 31
    .line 32
    const/4 v1, 0x6

    .line 33
    iget-object v3, p0, Lqv0/g;->f:Lm1/t;

    .line 34
    .line 35
    invoke-direct {p1, v3, v1}, Lh2/t2;-><init>(Lm1/t;I)V

    .line 36
    .line 37
    .line 38
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-static {p1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    new-instance v1, Lq61/k;

    .line 47
    .line 48
    const/4 v3, 0x0

    .line 49
    const/4 v4, 0x2

    .line 50
    iget-object v5, p0, Lqv0/g;->g:Ll2/b1;

    .line 51
    .line 52
    invoke-direct {v1, v5, v3, v4}, Lq61/k;-><init>(Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    iput v2, p0, Lqv0/g;->e:I

    .line 56
    .line 57
    invoke-static {v1, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    if-ne p0, v0, :cond_2

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    :goto_1
    return-object v0

    .line 67
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 68
    .line 69
    iget v1, p0, Lqv0/g;->e:I

    .line 70
    .line 71
    const/4 v2, 0x1

    .line 72
    if-eqz v1, :cond_4

    .line 73
    .line 74
    if-ne v1, v2, :cond_3

    .line 75
    .line 76
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 81
    .line 82
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 83
    .line 84
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    new-instance p1, Lh2/t2;

    .line 92
    .line 93
    const/4 v1, 0x4

    .line 94
    iget-object v3, p0, Lqv0/g;->f:Lm1/t;

    .line 95
    .line 96
    invoke-direct {p1, v3, v1}, Lh2/t2;-><init>(Lm1/t;I)V

    .line 97
    .line 98
    .line 99
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    invoke-static {p1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    new-instance v1, Lq61/k;

    .line 108
    .line 109
    const/4 v3, 0x0

    .line 110
    const/4 v4, 0x1

    .line 111
    iget-object v5, p0, Lqv0/g;->g:Ll2/b1;

    .line 112
    .line 113
    invoke-direct {v1, v5, v3, v4}, Lq61/k;-><init>(Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 114
    .line 115
    .line 116
    iput v2, p0, Lqv0/g;->e:I

    .line 117
    .line 118
    invoke-static {v1, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    if-ne p0, v0, :cond_5

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    :goto_3
    return-object v0

    .line 128
    nop

    .line 129
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
