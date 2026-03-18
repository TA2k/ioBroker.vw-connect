.class public final Lh50/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh50/o;


# direct methods
.method public constructor <init>(Lh50/o;ILkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lh50/m;->d:I

    .line 1
    iput-object p1, p0, Lh50/m;->f:Lh50/o;

    iput p2, p0, Lh50/m;->e:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lh50/o;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lh50/m;->d:I

    .line 2
    iput-object p1, p0, Lh50/m;->f:Lh50/o;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lh50/m;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh50/m;

    .line 7
    .line 8
    iget-object p0, p0, Lh50/m;->f:Lh50/o;

    .line 9
    .line 10
    invoke-direct {p1, p0, p2}, Lh50/m;-><init>(Lh50/o;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-object p1

    .line 14
    :pswitch_0
    new-instance p1, Lh50/m;

    .line 15
    .line 16
    iget-object v0, p0, Lh50/m;->f:Lh50/o;

    .line 17
    .line 18
    iget p0, p0, Lh50/m;->e:I

    .line 19
    .line 20
    invoke-direct {p1, v0, p0, p2}, Lh50/m;-><init>(Lh50/o;ILkotlin/coroutines/Continuation;)V

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
    iget v0, p0, Lh50/m;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh50/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh50/m;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh50/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh50/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh50/m;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh50/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    return-object p1

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lh50/m;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Lh50/m;->f:Lh50/o;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v3, p0, Lh50/m;->e:I

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    if-eqz v3, :cond_1

    .line 16
    .line 17
    if-ne v3, v4, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    sget-object p1, Lh50/o;->p:Lgy0/j;

    .line 35
    .line 36
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    check-cast p1, Lh50/k;

    .line 41
    .line 42
    iput v4, p0, Lh50/m;->e:I

    .line 43
    .line 44
    invoke-static {v2, p1, p0}, Lh50/o;->h(Lh50/o;Lh50/k;Lrx0/c;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    if-ne p1, v0, :cond_2

    .line 49
    .line 50
    move-object v1, v0

    .line 51
    goto :goto_1

    .line 52
    :cond_2
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 53
    .line 54
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    if-eqz p0, :cond_3

    .line 59
    .line 60
    sget-object p0, Lh50/o;->p:Lgy0/j;

    .line 61
    .line 62
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    move-object v3, p0

    .line 67
    check-cast v3, Lh50/k;

    .line 68
    .line 69
    const/4 v7, 0x1

    .line 70
    const/4 v8, 0x7

    .line 71
    const/4 v4, 0x0

    .line 72
    const/4 v5, 0x0

    .line 73
    const/4 v6, 0x0

    .line 74
    invoke-static/range {v3 .. v8}, Lh50/k;->a(Lh50/k;Ljava/lang/String;Lh50/j;ZZI)Lh50/k;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    iget-object p0, v2, Lh50/o;->h:Ltr0/b;

    .line 83
    .line 84
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    :goto_1
    return-object v1

    .line 88
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 89
    .line 90
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    sget-object p1, Lh50/o;->p:Lgy0/j;

    .line 94
    .line 95
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    move-object v3, p1

    .line 100
    check-cast v3, Lh50/k;

    .line 101
    .line 102
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    check-cast p1, Lh50/k;

    .line 107
    .line 108
    iget-object p1, p1, Lh50/k;->b:Lh50/j;

    .line 109
    .line 110
    iget p0, p0, Lh50/m;->e:I

    .line 111
    .line 112
    iget-object v0, p1, Lh50/j;->a:Lgy0/g;

    .line 113
    .line 114
    iget-object p1, p1, Lh50/j;->c:Ljava/lang/String;

    .line 115
    .line 116
    const-string v4, "range"

    .line 117
    .line 118
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    new-instance v5, Lh50/j;

    .line 122
    .line 123
    invoke-direct {v5, v0, p0, p1}, Lh50/j;-><init>(Lgy0/g;ILjava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const/4 v7, 0x0

    .line 127
    const/16 v8, 0xd

    .line 128
    .line 129
    const/4 v4, 0x0

    .line 130
    const/4 v6, 0x0

    .line 131
    invoke-static/range {v3 .. v8}, Lh50/k;->a(Lh50/k;Ljava/lang/String;Lh50/j;ZZI)Lh50/k;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 136
    .line 137
    .line 138
    return-object v1

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
