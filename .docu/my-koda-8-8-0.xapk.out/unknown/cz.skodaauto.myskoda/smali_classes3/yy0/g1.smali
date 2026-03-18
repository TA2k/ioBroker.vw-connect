.class public final Lyy0/g1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:[Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/o;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lyy0/g1;->d:I

    .line 1
    iput-object p1, p0, Lyy0/g1;->h:Ljava/lang/Object;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lkotlin/coroutines/Continuation;Lay0/q;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lyy0/g1;->d:I

    .line 2
    iput-object p2, p0, Lyy0/g1;->h:Ljava/lang/Object;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lyy0/g1;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p2, [Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance v0, Lyy0/g1;

    .line 13
    .line 14
    iget-object p0, p0, Lyy0/g1;->h:Ljava/lang/Object;

    .line 15
    .line 16
    invoke-direct {v0, p0, p3}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, v0, Lyy0/g1;->f:Lyy0/j;

    .line 20
    .line 21
    iput-object p2, v0, Lyy0/g1;->g:[Ljava/lang/Object;

    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Lyy0/g1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_0
    new-instance v0, Lyy0/g1;

    .line 31
    .line 32
    iget-object p0, p0, Lyy0/g1;->h:Ljava/lang/Object;

    .line 33
    .line 34
    invoke-direct {v0, p3, p0}, Lyy0/g1;-><init>(Lkotlin/coroutines/Continuation;Lay0/q;)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lyy0/g1;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lyy0/g1;->g:[Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lyy0/g1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lyy0/g1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lyy0/g1;->e:I

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    if-eq v1, v3, :cond_1

    .line 15
    .line 16
    if-ne v1, v2, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    iget-object v1, p0, Lyy0/g1;->f:Lyy0/j;

    .line 31
    .line 32
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Lyy0/g1;->f:Lyy0/j;

    .line 40
    .line 41
    iget-object p1, p0, Lyy0/g1;->g:[Ljava/lang/Object;

    .line 42
    .line 43
    const/4 v4, 0x0

    .line 44
    aget-object v4, p1, v4

    .line 45
    .line 46
    aget-object p1, p1, v3

    .line 47
    .line 48
    iput-object v1, p0, Lyy0/g1;->f:Lyy0/j;

    .line 49
    .line 50
    iput v3, p0, Lyy0/g1;->e:I

    .line 51
    .line 52
    iget-object v3, p0, Lyy0/g1;->h:Ljava/lang/Object;

    .line 53
    .line 54
    invoke-interface {v3, v4, p1, p0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    if-ne p1, v0, :cond_3

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_3
    :goto_0
    const/4 v3, 0x0

    .line 62
    iput-object v3, p0, Lyy0/g1;->f:Lyy0/j;

    .line 63
    .line 64
    iput v2, p0, Lyy0/g1;->e:I

    .line 65
    .line 66
    invoke-interface {v1, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-ne p0, v0, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    :goto_2
    return-object v0

    .line 76
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 77
    .line 78
    iget v1, p0, Lyy0/g1;->e:I

    .line 79
    .line 80
    const/4 v2, 0x2

    .line 81
    const/4 v3, 0x1

    .line 82
    if-eqz v1, :cond_7

    .line 83
    .line 84
    if-eq v1, v3, :cond_6

    .line 85
    .line 86
    if-ne v1, v2, :cond_5

    .line 87
    .line 88
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 93
    .line 94
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 95
    .line 96
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p0

    .line 100
    :cond_6
    iget-object v1, p0, Lyy0/g1;->f:Lyy0/j;

    .line 101
    .line 102
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    move-object v10, p0

    .line 106
    goto :goto_3

    .line 107
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iget-object v1, p0, Lyy0/g1;->f:Lyy0/j;

    .line 111
    .line 112
    iget-object p1, p0, Lyy0/g1;->g:[Ljava/lang/Object;

    .line 113
    .line 114
    const/4 v4, 0x0

    .line 115
    aget-object v6, p1, v4

    .line 116
    .line 117
    aget-object v7, p1, v3

    .line 118
    .line 119
    aget-object v8, p1, v2

    .line 120
    .line 121
    const/4 v4, 0x3

    .line 122
    aget-object v9, p1, v4

    .line 123
    .line 124
    iput-object v1, p0, Lyy0/g1;->f:Lyy0/j;

    .line 125
    .line 126
    iput v3, p0, Lyy0/g1;->e:I

    .line 127
    .line 128
    iget-object v5, p0, Lyy0/g1;->h:Ljava/lang/Object;

    .line 129
    .line 130
    move-object v10, p0

    .line 131
    invoke-interface/range {v5 .. v10}, Lay0/q;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    if-ne p1, v0, :cond_8

    .line 136
    .line 137
    goto :goto_5

    .line 138
    :cond_8
    :goto_3
    const/4 p0, 0x0

    .line 139
    iput-object p0, v10, Lyy0/g1;->f:Lyy0/j;

    .line 140
    .line 141
    iput v2, v10, Lyy0/g1;->e:I

    .line 142
    .line 143
    invoke-interface {v1, p1, v10}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    if-ne p0, v0, :cond_9

    .line 148
    .line 149
    goto :goto_5

    .line 150
    :cond_9
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 151
    .line 152
    :goto_5
    return-object v0

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
