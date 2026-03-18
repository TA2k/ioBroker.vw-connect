.class public final Lzh/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lzh/m;


# direct methods
.method public synthetic constructor <init>(Lzh/m;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lzh/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzh/l;->f:Lzh/m;

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
    iget p1, p0, Lzh/l;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lzh/l;

    .line 7
    .line 8
    iget-object p0, p0, Lzh/l;->f:Lzh/m;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lzh/l;-><init>(Lzh/m;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lzh/l;

    .line 16
    .line 17
    iget-object p0, p0, Lzh/l;->f:Lzh/m;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lzh/l;-><init>(Lzh/m;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lzh/l;->d:I

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
    invoke-virtual {p0, p1, p2}, Lzh/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lzh/l;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lzh/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lzh/l;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lzh/l;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lzh/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lzh/l;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 6
    .line 7
    iget-object v3, p0, Lzh/l;->f:Lzh/m;

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    iget v5, p0, Lzh/l;->e:I

    .line 16
    .line 17
    if-eqz v5, :cond_1

    .line 18
    .line 19
    if-ne v5, v4, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    new-instance p1, Lkotlin/jvm/internal/d0;

    .line 35
    .line 36
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 37
    .line 38
    .line 39
    iget-object v2, v3, Lzh/m;->i:Lai/d;

    .line 40
    .line 41
    new-instance v5, Lzb/f0;

    .line 42
    .line 43
    iget v6, v3, Lzh/m;->j:I

    .line 44
    .line 45
    sget v7, Lmy0/c;->g:I

    .line 46
    .line 47
    const-wide/16 v7, 0x5

    .line 48
    .line 49
    sget-object v9, Lmy0/e;->h:Lmy0/e;

    .line 50
    .line 51
    invoke-static {v7, v8, v9}, Lmy0/h;->t(JLmy0/e;)J

    .line 52
    .line 53
    .line 54
    move-result-wide v7

    .line 55
    invoke-direct {v5, v6, v7, v8}, Lzb/f0;-><init>(IJ)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v2, v5}, Lai/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    check-cast v2, Lyy0/i;

    .line 63
    .line 64
    new-instance v5, Ly70/c0;

    .line 65
    .line 66
    const/4 v6, 0x6

    .line 67
    invoke-direct {v5, v6, v3, p1}, Ly70/c0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iput v4, p0, Lzh/l;->e:I

    .line 71
    .line 72
    invoke-interface {v2, v5, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    if-ne p0, v0, :cond_2

    .line 77
    .line 78
    move-object v1, v0

    .line 79
    :cond_2
    :goto_0
    return-object v1

    .line 80
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 81
    .line 82
    iget v5, p0, Lzh/l;->e:I

    .line 83
    .line 84
    if-eqz v5, :cond_4

    .line 85
    .line 86
    if-ne v5, v4, :cond_3

    .line 87
    .line 88
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 93
    .line 94
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p0

    .line 98
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    iget-object p1, v3, Lzh/m;->n:Lyy0/c2;

    .line 102
    .line 103
    new-instance v2, Lzh/k;

    .line 104
    .line 105
    invoke-direct {v2, v3, v4}, Lzh/k;-><init>(Lzh/m;I)V

    .line 106
    .line 107
    .line 108
    new-instance v5, Lzh/k;

    .line 109
    .line 110
    const/4 v6, 0x2

    .line 111
    invoke-direct {v5, v3, v6}, Lzh/k;-><init>(Lzh/m;I)V

    .line 112
    .line 113
    .line 114
    iput v4, p0, Lzh/l;->e:I

    .line 115
    .line 116
    invoke-static {p1, v2, v5, p0}, Lzb/b;->x(Lyy0/i1;Lay0/a;Lay0/a;Lrx0/i;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    if-ne p0, v0, :cond_5

    .line 121
    .line 122
    move-object v1, v0

    .line 123
    :cond_5
    :goto_1
    return-object v1

    .line 124
    nop

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
