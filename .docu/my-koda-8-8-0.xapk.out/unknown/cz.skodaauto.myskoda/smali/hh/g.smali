.class public final Lhh/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lhh/h;


# direct methods
.method public synthetic constructor <init>(Lhh/h;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhh/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhh/g;->f:Lhh/h;

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
    iget p1, p0, Lhh/g;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lhh/g;

    .line 7
    .line 8
    iget-object p0, p0, Lhh/g;->f:Lhh/h;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lhh/g;-><init>(Lhh/h;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lhh/g;

    .line 16
    .line 17
    iget-object p0, p0, Lhh/g;->f:Lhh/h;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lhh/g;-><init>(Lhh/h;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lhh/g;->d:I

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
    invoke-virtual {p0, p1, p2}, Lhh/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lhh/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lhh/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lhh/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lhh/g;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lhh/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lhh/g;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const-string v3, "call to \'resume\' before \'invoke\' with coroutine"

    .line 7
    .line 8
    iget-object v4, p0, Lhh/g;->f:Lhh/h;

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
    iget v6, p0, Lhh/g;->e:I

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
    iget-object v3, v4, Lhh/h;->i:Lhh/c;

    .line 41
    .line 42
    new-instance v6, Lzb/f0;

    .line 43
    .line 44
    iget v7, v4, Lhh/h;->j:I

    .line 45
    .line 46
    sget v8, Lmy0/c;->g:I

    .line 47
    .line 48
    const-wide/16 v8, 0x5

    .line 49
    .line 50
    sget-object v10, Lmy0/e;->h:Lmy0/e;

    .line 51
    .line 52
    invoke-static {v8, v9, v10}, Lmy0/h;->t(JLmy0/e;)J

    .line 53
    .line 54
    .line 55
    move-result-wide v8

    .line 56
    invoke-direct {v6, v7, v8, v9}, Lzb/f0;-><init>(IJ)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v3, v6}, Lhh/c;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    check-cast v3, Lyy0/i;

    .line 64
    .line 65
    new-instance v6, Lhg/s;

    .line 66
    .line 67
    invoke-direct {v6, v2, v4, p1}, Lhg/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iput v5, p0, Lhh/g;->e:I

    .line 71
    .line 72
    invoke-interface {v3, v6, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    iget v6, p0, Lhh/g;->e:I

    .line 83
    .line 84
    if-eqz v6, :cond_4

    .line 85
    .line 86
    if-ne v6, v5, :cond_3

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
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iget-object p1, v4, Lhh/h;->l:Lyy0/c2;

    .line 102
    .line 103
    new-instance v3, Lhh/f;

    .line 104
    .line 105
    invoke-direct {v3, v4, v5}, Lhh/f;-><init>(Lhh/h;I)V

    .line 106
    .line 107
    .line 108
    new-instance v6, Lhh/f;

    .line 109
    .line 110
    invoke-direct {v6, v4, v2}, Lhh/f;-><init>(Lhh/h;I)V

    .line 111
    .line 112
    .line 113
    iput v5, p0, Lhh/g;->e:I

    .line 114
    .line 115
    invoke-static {p1, v3, v6, p0}, Lzb/b;->x(Lyy0/i1;Lay0/a;Lay0/a;Lrx0/i;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    if-ne p0, v0, :cond_5

    .line 120
    .line 121
    move-object v1, v0

    .line 122
    :cond_5
    :goto_1
    return-object v1

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
