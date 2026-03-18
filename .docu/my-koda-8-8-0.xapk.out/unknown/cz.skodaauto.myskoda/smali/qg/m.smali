.class public final Lqg/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lqg/n;


# direct methods
.method public synthetic constructor <init>(Lqg/n;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lqg/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqg/m;->f:Lqg/n;

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
    iget p1, p0, Lqg/m;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lqg/m;

    .line 7
    .line 8
    iget-object p0, p0, Lqg/m;->f:Lqg/n;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lqg/m;-><init>(Lqg/n;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lqg/m;

    .line 16
    .line 17
    iget-object p0, p0, Lqg/m;->f:Lqg/n;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lqg/m;-><init>(Lqg/n;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lqg/m;->d:I

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
    invoke-virtual {p0, p1, p2}, Lqg/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lqg/m;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lqg/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lqg/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lqg/m;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lqg/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 4

    .line 1
    iget v0, p0, Lqg/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lqg/m;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object v3, p0, Lqg/m;->f:Lqg/n;

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v2, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v3, Lqg/n;->j:Llo0/b;

    .line 33
    .line 34
    iput v2, p0, Lqg/m;->e:I

    .line 35
    .line 36
    invoke-virtual {p1, p0}, Llo0/b;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    if-ne p1, v0, :cond_2

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_2
    :goto_0
    check-cast p1, Llx0/o;

    .line 44
    .line 45
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 46
    .line 47
    instance-of p1, p0, Llx0/n;

    .line 48
    .line 49
    if-nez p1, :cond_3

    .line 50
    .line 51
    move-object p1, p0

    .line 52
    check-cast p1, Lkg/d0;

    .line 53
    .line 54
    invoke-static {v3, p1}, Lqg/n;->a(Lqg/n;Lkg/d0;)V

    .line 55
    .line 56
    .line 57
    :cond_3
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    if-eqz p0, :cond_4

    .line 62
    .line 63
    iget-object p1, v3, Lqg/n;->l:Lyy0/c2;

    .line 64
    .line 65
    const/4 v0, 0x0

    .line 66
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-static {p0, p1, v0}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    :cond_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    :goto_1
    return-object v0

    .line 76
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 77
    .line 78
    iget v1, p0, Lqg/m;->e:I

    .line 79
    .line 80
    const/4 v2, 0x1

    .line 81
    iget-object v3, p0, Lqg/m;->f:Lqg/n;

    .line 82
    .line 83
    if-eqz v1, :cond_6

    .line 84
    .line 85
    if-ne v1, v2, :cond_5

    .line 86
    .line 87
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 92
    .line 93
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 94
    .line 95
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    iget-object p1, v3, Lqg/n;->f:Ljd/b;

    .line 103
    .line 104
    iget-object v1, v3, Lqg/n;->d:Ljava/lang/String;

    .line 105
    .line 106
    iput v2, p0, Lqg/m;->e:I

    .line 107
    .line 108
    invoke-virtual {p1, v1, p0}, Ljd/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    if-ne p1, v0, :cond_7

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_7
    :goto_2
    check-cast p1, Llx0/o;

    .line 116
    .line 117
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 118
    .line 119
    instance-of p1, p0, Llx0/n;

    .line 120
    .line 121
    if-nez p1, :cond_8

    .line 122
    .line 123
    move-object p1, p0

    .line 124
    check-cast p1, Lkg/d0;

    .line 125
    .line 126
    invoke-static {v3, p1}, Lqg/n;->a(Lqg/n;Lkg/d0;)V

    .line 127
    .line 128
    .line 129
    :cond_8
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    if-eqz p0, :cond_9

    .line 134
    .line 135
    iget-object p1, v3, Lqg/n;->l:Lyy0/c2;

    .line 136
    .line 137
    const/4 v0, 0x0

    .line 138
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-static {p0, p1, v0}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    :cond_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 146
    .line 147
    :goto_3
    return-object v0

    .line 148
    nop

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
