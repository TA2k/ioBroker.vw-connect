.class public final Lq40/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lq40/c;


# direct methods
.method public synthetic constructor <init>(Lq40/c;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lq40/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lq40/b;->f:Lq40/c;

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
    iget p1, p0, Lq40/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lq40/b;

    .line 7
    .line 8
    iget-object p0, p0, Lq40/b;->f:Lq40/c;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lq40/b;-><init>(Lq40/c;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lq40/b;

    .line 16
    .line 17
    iget-object p0, p0, Lq40/b;->f:Lq40/c;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lq40/b;-><init>(Lq40/c;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lq40/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Lq40/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lq40/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lq40/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lq40/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lq40/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lq40/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lq40/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lq40/b;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object v3, p0, Lq40/b;->f:Lq40/c;

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    const/4 v5, 0x1

    .line 16
    if-eqz v1, :cond_3

    .line 17
    .line 18
    if-eq v1, v5, :cond_2

    .line 19
    .line 20
    if-ne v1, v4, :cond_1

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    move-object v0, v2

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object p1, v3, Lq40/c;->m:Lo40/f;

    .line 43
    .line 44
    iput v5, p0, Lq40/b;->e:I

    .line 45
    .line 46
    invoke-virtual {p1, v2, p0}, Lo40/f;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    if-ne p1, v0, :cond_4

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_4
    :goto_0
    check-cast p1, Lyy0/i;

    .line 54
    .line 55
    new-instance v1, Lma0/c;

    .line 56
    .line 57
    const/16 v5, 0xf

    .line 58
    .line 59
    invoke-direct {v1, v3, v5}, Lma0/c;-><init>(Ljava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    iput v4, p0, Lq40/b;->e:I

    .line 63
    .line 64
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-ne p0, v0, :cond_0

    .line 69
    .line 70
    :goto_1
    return-object v0

    .line 71
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 72
    .line 73
    iget v1, p0, Lq40/b;->e:I

    .line 74
    .line 75
    iget-object v2, p0, Lq40/b;->f:Lq40/c;

    .line 76
    .line 77
    const/4 v3, 0x2

    .line 78
    const/4 v4, 0x1

    .line 79
    if-eqz v1, :cond_7

    .line 80
    .line 81
    if-eq v1, v4, :cond_6

    .line 82
    .line 83
    if-ne v1, v3, :cond_5

    .line 84
    .line 85
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 92
    .line 93
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    iget-object p1, v2, Lq40/c;->i:Lnn0/j;

    .line 105
    .line 106
    iput v4, p0, Lq40/b;->e:I

    .line 107
    .line 108
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    iget-object p1, p1, Lnn0/j;->a:Lln0/g;

    .line 112
    .line 113
    iget-object p1, p1, Lln0/g;->c:Lyy0/l1;

    .line 114
    .line 115
    if-ne p1, v0, :cond_8

    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_8
    :goto_2
    check-cast p1, Lyy0/i;

    .line 119
    .line 120
    new-instance v1, Lnz/g;

    .line 121
    .line 122
    const/4 v4, 0x0

    .line 123
    const/16 v5, 0xb

    .line 124
    .line 125
    invoke-direct {v1, v2, v4, v5}, Lnz/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 126
    .line 127
    .line 128
    iput v3, p0, Lq40/b;->e:I

    .line 129
    .line 130
    invoke-static {v1, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    if-ne p0, v0, :cond_9

    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_9
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 138
    .line 139
    :goto_4
    return-object v0

    .line 140
    nop

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
