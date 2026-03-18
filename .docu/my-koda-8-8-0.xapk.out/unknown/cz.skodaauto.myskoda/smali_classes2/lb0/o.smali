.class public final Llb0/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Lyy0/j;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljb0/e0;

.field public final synthetic h:Llb0/p;

.field public final synthetic i:Z

.field public j:Lyy0/j;

.field public k:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Ljb0/e0;Llb0/p;Z)V
    .locals 0

    .line 1
    iput-object p2, p0, Llb0/o;->g:Ljb0/e0;

    .line 2
    .line 3
    iput-object p3, p0, Llb0/o;->h:Llb0/p;

    .line 4
    .line 5
    iput-boolean p4, p0, Llb0/o;->i:Z

    .line 6
    .line 7
    const/4 p2, 0x3

    .line 8
    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    new-instance v0, Llb0/o;

    .line 6
    .line 7
    iget-object v1, p0, Llb0/o;->h:Llb0/p;

    .line 8
    .line 9
    iget-boolean v2, p0, Llb0/o;->i:Z

    .line 10
    .line 11
    iget-object p0, p0, Llb0/o;->g:Ljb0/e0;

    .line 12
    .line 13
    invoke-direct {v0, p3, p0, v1, v2}, Llb0/o;-><init>(Lkotlin/coroutines/Continuation;Ljb0/e0;Llb0/p;Z)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Llb0/o;->e:Lyy0/j;

    .line 17
    .line 18
    iput-object p2, v0, Llb0/o;->f:Ljava/lang/Object;

    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Llb0/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Llb0/o;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, p0, Llb0/o;->g:Ljb0/e0;

    .line 8
    .line 9
    const/4 v4, 0x2

    .line 10
    const/4 v5, 0x1

    .line 11
    const/4 v6, 0x0

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    if-eq v1, v5, :cond_1

    .line 15
    .line 16
    if-ne v1, v4, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto/16 :goto_4

    .line 22
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
    iget-object v1, p0, Llb0/o;->k:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v7, p0, Llb0/o;->j:Lyy0/j;

    .line 34
    .line 35
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object v7, p0, Llb0/o;->e:Lyy0/j;

    .line 43
    .line 44
    iget-object p1, p0, Llb0/o;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Lss0/j0;

    .line 47
    .line 48
    iget-object v1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 49
    .line 50
    iput-object v6, p0, Llb0/o;->e:Lyy0/j;

    .line 51
    .line 52
    iput-object v6, p0, Llb0/o;->f:Ljava/lang/Object;

    .line 53
    .line 54
    iput-object v7, p0, Llb0/o;->j:Lyy0/j;

    .line 55
    .line 56
    iput-object v1, p0, Llb0/o;->k:Ljava/lang/String;

    .line 57
    .line 58
    iput v5, p0, Llb0/o;->d:I

    .line 59
    .line 60
    invoke-virtual {v3, v1, p0}, Ljb0/e0;->c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    if-ne p1, v0, :cond_3

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_3
    :goto_0
    check-cast p1, Lyy0/i;

    .line 68
    .line 69
    iget-object v8, v3, Ljb0/e0;->e:Lez0/c;

    .line 70
    .line 71
    new-instance v9, Lep0/f;

    .line 72
    .line 73
    const/4 v10, 0x6

    .line 74
    invoke-direct {v9, v3, v10}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 75
    .line 76
    .line 77
    new-instance v10, La2/c;

    .line 78
    .line 79
    const/16 v11, 0x1b

    .line 80
    .line 81
    invoke-direct {v10, v11, v3, v1, v6}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 82
    .line 83
    .line 84
    new-instance v1, Lbq0/i;

    .line 85
    .line 86
    const/16 v3, 0x18

    .line 87
    .line 88
    iget-object v11, p0, Llb0/o;->h:Llb0/p;

    .line 89
    .line 90
    invoke-direct {v1, v11, v6, v3}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 91
    .line 92
    .line 93
    invoke-static {p1, v8, v9, v10, v1}, Lbb/j0;->g(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;Lay0/k;)Lyy0/i;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    iget-object v1, v11, Llb0/p;->d:Llb0/q;

    .line 98
    .line 99
    invoke-virtual {v1}, Llb0/q;->invoke()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    check-cast v1, Lyy0/i;

    .line 104
    .line 105
    new-instance v3, Llb0/n;

    .line 106
    .line 107
    iget-boolean v8, p0, Llb0/o;->i:Z

    .line 108
    .line 109
    invoke-direct {v3, v8, v11, v6}, Llb0/n;-><init>(ZLlb0/p;Lkotlin/coroutines/Continuation;)V

    .line 110
    .line 111
    .line 112
    iput-object v6, p0, Llb0/o;->e:Lyy0/j;

    .line 113
    .line 114
    iput-object v6, p0, Llb0/o;->f:Ljava/lang/Object;

    .line 115
    .line 116
    iput-object v6, p0, Llb0/o;->j:Lyy0/j;

    .line 117
    .line 118
    iput-object v6, p0, Llb0/o;->k:Ljava/lang/String;

    .line 119
    .line 120
    iput v4, p0, Llb0/o;->d:I

    .line 121
    .line 122
    invoke-static {v7}, Lyy0/u;->s(Lyy0/j;)V

    .line 123
    .line 124
    .line 125
    new-array v4, v4, [Lyy0/i;

    .line 126
    .line 127
    const/4 v8, 0x0

    .line 128
    aput-object p1, v4, v8

    .line 129
    .line 130
    aput-object v1, v4, v5

    .line 131
    .line 132
    new-instance p1, Lyy0/g1;

    .line 133
    .line 134
    invoke-direct {p1, v3, v6}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 135
    .line 136
    .line 137
    sget-object v1, Lyy0/h1;->d:Lyy0/h1;

    .line 138
    .line 139
    invoke-static {v1, p1, p0, v7, v4}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 144
    .line 145
    if-ne p0, p1, :cond_4

    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_4
    move-object p0, v2

    .line 149
    :goto_1
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 150
    .line 151
    if-ne p0, p1, :cond_5

    .line 152
    .line 153
    goto :goto_2

    .line 154
    :cond_5
    move-object p0, v2

    .line 155
    :goto_2
    if-ne p0, v0, :cond_6

    .line 156
    .line 157
    :goto_3
    return-object v0

    .line 158
    :cond_6
    :goto_4
    return-object v2
.end method
