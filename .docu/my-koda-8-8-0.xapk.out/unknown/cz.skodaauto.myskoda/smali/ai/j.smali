.class public final Lai/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lai/l;


# direct methods
.method public synthetic constructor <init>(Lai/l;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lai/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lai/j;->f:Lai/l;

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
    iget p1, p0, Lai/j;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lai/j;

    .line 7
    .line 8
    iget-object p0, p0, Lai/j;->f:Lai/l;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lai/j;-><init>(Lai/l;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lai/j;

    .line 16
    .line 17
    iget-object p0, p0, Lai/j;->f:Lai/l;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lai/j;-><init>(Lai/l;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lai/j;->d:I

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
    invoke-virtual {p0, p1, p2}, Lai/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lai/j;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lai/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lai/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lai/j;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lai/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lai/j;->d:I

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
    iget-object v4, p0, Lai/j;->f:Lai/l;

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    iget v6, p0, Lai/j;->e:I

    .line 17
    .line 18
    if-eqz v6, :cond_1

    .line 19
    .line 20
    if-ne v6, v5, :cond_0

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    new-instance p1, Lkotlin/jvm/internal/d0;

    .line 36
    .line 37
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    new-instance v3, Lzb/f0;

    .line 41
    .line 42
    iget v6, v4, Lai/l;->g:I

    .line 43
    .line 44
    sget v7, Lmy0/c;->g:I

    .line 45
    .line 46
    const-wide/16 v7, 0x5

    .line 47
    .line 48
    sget-object v9, Lmy0/e;->h:Lmy0/e;

    .line 49
    .line 50
    invoke-static {v7, v8, v9}, Lmy0/h;->t(JLmy0/e;)J

    .line 51
    .line 52
    .line 53
    move-result-wide v7

    .line 54
    invoke-direct {v3, v6, v7, v8}, Lzb/f0;-><init>(IJ)V

    .line 55
    .line 56
    .line 57
    iget-object v6, v4, Lai/l;->f:La71/a0;

    .line 58
    .line 59
    iget-object v7, v4, Lai/l;->i:Ljava/lang/String;

    .line 60
    .line 61
    invoke-virtual {v6, v3, v7}, La71/a0;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    check-cast v3, Lyy0/i;

    .line 66
    .line 67
    new-instance v6, Lai/k;

    .line 68
    .line 69
    invoke-direct {v6, v2, v4, p1}, Lai/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iput v5, p0, Lai/j;->e:I

    .line 73
    .line 74
    invoke-interface {v3, v6, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    if-ne p0, v0, :cond_2

    .line 79
    .line 80
    move-object v1, v0

    .line 81
    :cond_2
    :goto_0
    return-object v1

    .line 82
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 83
    .line 84
    iget v6, p0, Lai/j;->e:I

    .line 85
    .line 86
    if-eqz v6, :cond_4

    .line 87
    .line 88
    if-ne v6, v5, :cond_3

    .line 89
    .line 90
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p0

    .line 100
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    iget-object p1, v4, Lai/l;->j:Lyy0/c2;

    .line 104
    .line 105
    new-instance v3, Lai/i;

    .line 106
    .line 107
    invoke-direct {v3, v4, v2}, Lai/i;-><init>(Lai/l;I)V

    .line 108
    .line 109
    .line 110
    new-instance v2, Lai/i;

    .line 111
    .line 112
    invoke-direct {v2, v4, v5}, Lai/i;-><init>(Lai/l;I)V

    .line 113
    .line 114
    .line 115
    iput v5, p0, Lai/j;->e:I

    .line 116
    .line 117
    invoke-static {p1, v3, v2, p0}, Lzb/b;->x(Lyy0/i1;Lay0/a;Lay0/a;Lrx0/i;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    if-ne p0, v0, :cond_5

    .line 122
    .line 123
    move-object v1, v0

    .line 124
    :cond_5
    :goto_1
    return-object v1

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
