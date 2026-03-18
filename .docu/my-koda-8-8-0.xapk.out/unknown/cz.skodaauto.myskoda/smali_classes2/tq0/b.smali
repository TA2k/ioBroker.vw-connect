.class public final Ltq0/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lyq0/n;

.field public final synthetic g:Ltq0/d;


# direct methods
.method public constructor <init>(Ltq0/d;Lyq0/n;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ltq0/b;->d:I

    .line 1
    iput-object p1, p0, Ltq0/b;->g:Ltq0/d;

    iput-object p2, p0, Ltq0/b;->f:Lyq0/n;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lyq0/n;Ltq0/d;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ltq0/b;->d:I

    .line 2
    iput-object p1, p0, Ltq0/b;->f:Lyq0/n;

    iput-object p2, p0, Ltq0/b;->g:Ltq0/d;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Ltq0/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltq0/b;

    .line 7
    .line 8
    iget-object v0, p0, Ltq0/b;->f:Lyq0/n;

    .line 9
    .line 10
    iget-object p0, p0, Ltq0/b;->g:Ltq0/d;

    .line 11
    .line 12
    invoke-direct {p1, v0, p0, p2}, Ltq0/b;-><init>(Lyq0/n;Ltq0/d;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_0
    new-instance p1, Ltq0/b;

    .line 17
    .line 18
    iget-object v0, p0, Ltq0/b;->g:Ltq0/d;

    .line 19
    .line 20
    iget-object p0, p0, Ltq0/b;->f:Lyq0/n;

    .line 21
    .line 22
    invoke-direct {p1, v0, p0, p2}, Ltq0/b;-><init>(Ltq0/d;Lyq0/n;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    return-object p1

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltq0/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltq0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltq0/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltq0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltq0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltq0/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltq0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Ltq0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ltq0/b;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Ltq0/b;->f:Lyq0/n;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

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
    sget-object p1, Ltq0/c;->a:[I

    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    aget p1, p1, v1

    .line 39
    .line 40
    if-ne p1, v3, :cond_2

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_2
    iget-object p1, p0, Ltq0/b;->g:Ltq0/d;

    .line 44
    .line 45
    iget-object p1, p1, Ltq0/d;->a:Lve0/u;

    .line 46
    .line 47
    iput v3, p0, Ltq0/b;->e:I

    .line 48
    .line 49
    const-string v1, "disabled_spin_warnings"

    .line 50
    .line 51
    invoke-virtual {p1, v1, p0}, Lve0/u;->g(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    if-ne p1, v0, :cond_3

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_3
    :goto_0
    check-cast p1, Ljava/util/Set;

    .line 59
    .line 60
    const/4 p0, 0x0

    .line 61
    if-eqz p1, :cond_4

    .line 62
    .line 63
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    invoke-interface {p1, v0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-ne p1, v3, :cond_4

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_4
    move v3, p0

    .line 75
    :goto_1
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    :goto_2
    return-object v0

    .line 80
    :pswitch_0
    iget-object v0, p0, Ltq0/b;->g:Ltq0/d;

    .line 81
    .line 82
    iget-object v0, v0, Ltq0/d;->a:Lve0/u;

    .line 83
    .line 84
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 85
    .line 86
    iget v2, p0, Ltq0/b;->e:I

    .line 87
    .line 88
    const-string v3, "disabled_spin_warnings"

    .line 89
    .line 90
    const/4 v4, 0x2

    .line 91
    const/4 v5, 0x1

    .line 92
    if-eqz v2, :cond_7

    .line 93
    .line 94
    if-eq v2, v5, :cond_6

    .line 95
    .line 96
    if-ne v2, v4, :cond_5

    .line 97
    .line 98
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 103
    .line 104
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 105
    .line 106
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw p0

    .line 110
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    iput v5, p0, Ltq0/b;->e:I

    .line 118
    .line 119
    invoke-virtual {v0, v3, p0}, Lve0/u;->g(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    if-ne p1, v1, :cond_8

    .line 124
    .line 125
    goto :goto_6

    .line 126
    :cond_8
    :goto_3
    check-cast p1, Ljava/util/Set;

    .line 127
    .line 128
    if-eqz p1, :cond_9

    .line 129
    .line 130
    check-cast p1, Ljava/lang/Iterable;

    .line 131
    .line 132
    invoke-static {p1}, Lmx0/q;->B0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    goto :goto_4

    .line 137
    :cond_9
    new-instance p1, Ljava/util/LinkedHashSet;

    .line 138
    .line 139
    invoke-direct {p1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 140
    .line 141
    .line 142
    :goto_4
    iget-object v2, p0, Ltq0/b;->f:Lyq0/n;

    .line 143
    .line 144
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    invoke-interface {p1, v2}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    iput v4, p0, Ltq0/b;->e:I

    .line 152
    .line 153
    invoke-virtual {v0, v3, p1, p0}, Lve0/u;->o(Ljava/lang/String;Ljava/util/Set;Lrx0/c;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    if-ne p0, v1, :cond_a

    .line 158
    .line 159
    goto :goto_6

    .line 160
    :cond_a
    :goto_5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 161
    .line 162
    :goto_6
    return-object v1

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
