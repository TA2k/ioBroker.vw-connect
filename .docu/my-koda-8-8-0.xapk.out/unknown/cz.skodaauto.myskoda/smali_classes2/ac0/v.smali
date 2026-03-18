.class public final Lac0/v;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lac0/w;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lac0/w;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lac0/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lac0/v;->f:Lac0/w;

    .line 4
    .line 5
    iput-object p2, p0, Lac0/v;->g:Ljava/lang/String;

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
    iget p1, p0, Lac0/v;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lac0/v;

    .line 7
    .line 8
    iget-object v0, p0, Lac0/v;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lac0/v;->f:Lac0/w;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lac0/v;-><init>(Lac0/w;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lac0/v;

    .line 18
    .line 19
    iget-object v0, p0, Lac0/v;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lac0/v;->f:Lac0/w;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lac0/v;-><init>(Lac0/w;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lac0/v;->d:I

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
    invoke-virtual {p0, p1, p2}, Lac0/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lac0/v;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lac0/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lac0/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lac0/v;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lac0/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 3

    .line 1
    iget v0, p0, Lac0/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lac0/v;->e:I

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
    iput v2, p0, Lac0/v;->e:I

    .line 31
    .line 32
    const-wide/16 v1, 0xbb8

    .line 33
    .line 34
    invoke-static {v1, v2, p0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    if-ne p1, v0, :cond_2

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_2
    :goto_0
    new-instance p1, Lac0/a;

    .line 42
    .line 43
    const/16 v0, 0xb

    .line 44
    .line 45
    iget-object v1, p0, Lac0/v;->g:Ljava/lang/String;

    .line 46
    .line 47
    invoke-direct {p1, v1, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 48
    .line 49
    .line 50
    const/4 v0, 0x0

    .line 51
    iget-object p0, p0, Lac0/v;->f:Lac0/w;

    .line 52
    .line 53
    invoke-static {v0, p0, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 54
    .line 55
    .line 56
    :try_start_0
    invoke-static {p0, v1}, Lac0/w;->g(Lac0/w;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 57
    .line 58
    .line 59
    :catch_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    :goto_1
    return-object v0

    .line 62
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 63
    .line 64
    iget v1, p0, Lac0/v;->e:I

    .line 65
    .line 66
    const/4 v2, 0x1

    .line 67
    if-eqz v1, :cond_4

    .line 68
    .line 69
    if-ne v1, v2, :cond_3

    .line 70
    .line 71
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 78
    .line 79
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p0

    .line 83
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    iput v2, p0, Lac0/v;->e:I

    .line 87
    .line 88
    const-wide/16 v1, 0xbb8

    .line 89
    .line 90
    invoke-static {v1, v2, p0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    if-ne p1, v0, :cond_5

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_5
    :goto_2
    iget-object p1, p0, Lac0/v;->f:Lac0/w;

    .line 98
    .line 99
    iget-object p1, p1, Lac0/w;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 100
    .line 101
    new-instance v0, Ldc0/b;

    .line 102
    .line 103
    iget-object p0, p0, Lac0/v;->g:Ljava/lang/String;

    .line 104
    .line 105
    invoke-direct {v0, p0}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    check-cast p1, Lac0/l;

    .line 113
    .line 114
    if-eqz p1, :cond_6

    .line 115
    .line 116
    iget-object p1, p1, Lac0/l;->b:Lyy0/i1;

    .line 117
    .line 118
    new-instance v0, Lne0/e;

    .line 119
    .line 120
    new-instance v1, Ldc0/a;

    .line 121
    .line 122
    const/4 v2, 0x0

    .line 123
    invoke-direct {v1, p0, v2}, Ldc0/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-direct {v0, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    invoke-interface {p1, v0}, Lyy0/i1;->a(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    :cond_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    :goto_3
    return-object v0

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
