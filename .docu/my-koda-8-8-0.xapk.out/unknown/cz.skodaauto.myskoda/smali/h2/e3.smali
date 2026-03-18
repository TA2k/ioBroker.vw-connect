.class public final Lh2/e3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lm1/t;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Li2/z;

.field public final synthetic i:Lgy0/j;


# direct methods
.method public synthetic constructor <init>(Lm1/t;Lay0/k;Li2/z;Lgy0/j;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p6, p0, Lh2/e3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/e3;->f:Lm1/t;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/e3;->g:Lay0/k;

    .line 6
    .line 7
    iput-object p3, p0, Lh2/e3;->h:Li2/z;

    .line 8
    .line 9
    iput-object p4, p0, Lh2/e3;->i:Lgy0/j;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget p1, p0, Lh2/e3;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh2/e3;

    .line 7
    .line 8
    iget-object v4, p0, Lh2/e3;->i:Lgy0/j;

    .line 9
    .line 10
    const/4 v6, 0x1

    .line 11
    iget-object v1, p0, Lh2/e3;->f:Lm1/t;

    .line 12
    .line 13
    iget-object v2, p0, Lh2/e3;->g:Lay0/k;

    .line 14
    .line 15
    iget-object v3, p0, Lh2/e3;->h:Li2/z;

    .line 16
    .line 17
    move-object v5, p2

    .line 18
    invoke-direct/range {v0 .. v6}, Lh2/e3;-><init>(Lm1/t;Lay0/k;Li2/z;Lgy0/j;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    :pswitch_0
    move-object v5, p2

    .line 23
    new-instance v1, Lh2/e3;

    .line 24
    .line 25
    move-object v6, v5

    .line 26
    iget-object v5, p0, Lh2/e3;->i:Lgy0/j;

    .line 27
    .line 28
    const/4 v7, 0x0

    .line 29
    iget-object v2, p0, Lh2/e3;->f:Lm1/t;

    .line 30
    .line 31
    iget-object v3, p0, Lh2/e3;->g:Lay0/k;

    .line 32
    .line 33
    iget-object v4, p0, Lh2/e3;->h:Li2/z;

    .line 34
    .line 35
    invoke-direct/range {v1 .. v7}, Lh2/e3;-><init>(Lm1/t;Lay0/k;Li2/z;Lgy0/j;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    return-object v1

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh2/e3;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh2/e3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh2/e3;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh2/e3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh2/e3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh2/e3;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh2/e3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, Lh2/e3;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v5, p0, Lh2/e3;->e:I

    .line 15
    .line 16
    if-eqz v5, :cond_1

    .line 17
    .line 18
    if-ne v5, v3, :cond_0

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iput v3, p0, Lh2/e3;->e:I

    .line 34
    .line 35
    sget p1, Lh2/m3;->a:F

    .line 36
    .line 37
    new-instance p1, Lh2/t2;

    .line 38
    .line 39
    iget-object v6, p0, Lh2/e3;->f:Lm1/t;

    .line 40
    .line 41
    invoke-direct {p1, v6, v1}, Lh2/t2;-><init>(Lm1/t;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    new-instance v5, Le1/b0;

    .line 49
    .line 50
    const/4 v10, 0x1

    .line 51
    iget-object v7, p0, Lh2/e3;->g:Lay0/k;

    .line 52
    .line 53
    iget-object v8, p0, Lh2/e3;->h:Li2/z;

    .line 54
    .line 55
    iget-object v9, p0, Lh2/e3;->i:Lgy0/j;

    .line 56
    .line 57
    invoke-direct/range {v5 .. v10}, Le1/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1, v5, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    if-ne p0, v0, :cond_2

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_2
    move-object p0, v4

    .line 68
    :goto_0
    if-ne p0, v0, :cond_3

    .line 69
    .line 70
    move-object v4, v0

    .line 71
    :cond_3
    :goto_1
    return-object v4

    .line 72
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 73
    .line 74
    iget v5, p0, Lh2/e3;->e:I

    .line 75
    .line 76
    if-eqz v5, :cond_5

    .line 77
    .line 78
    if-ne v5, v3, :cond_4

    .line 79
    .line 80
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    iput v3, p0, Lh2/e3;->e:I

    .line 94
    .line 95
    sget p1, Lh2/m3;->a:F

    .line 96
    .line 97
    new-instance p1, Lh2/t2;

    .line 98
    .line 99
    iget-object v6, p0, Lh2/e3;->f:Lm1/t;

    .line 100
    .line 101
    invoke-direct {p1, v6, v1}, Lh2/t2;-><init>(Lm1/t;I)V

    .line 102
    .line 103
    .line 104
    invoke-static {p1}, Ll2/b;->u(Lay0/a;)Lyy0/m1;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    new-instance v5, Le1/b0;

    .line 109
    .line 110
    const/4 v10, 0x1

    .line 111
    iget-object v7, p0, Lh2/e3;->g:Lay0/k;

    .line 112
    .line 113
    iget-object v8, p0, Lh2/e3;->h:Li2/z;

    .line 114
    .line 115
    iget-object v9, p0, Lh2/e3;->i:Lgy0/j;

    .line 116
    .line 117
    invoke-direct/range {v5 .. v10}, Le1/b0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1, v5, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    if-ne p0, v0, :cond_6

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_6
    move-object p0, v4

    .line 128
    :goto_2
    if-ne p0, v0, :cond_7

    .line 129
    .line 130
    move-object v4, v0

    .line 131
    :cond_7
    :goto_3
    return-object v4

    .line 132
    nop

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
