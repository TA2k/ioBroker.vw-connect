.class public final Lf40/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf40/u;


# direct methods
.method public constructor <init>(Lf40/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/u0;->a:Lf40/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lf40/u0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lf40/t0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lf40/t0;

    .line 7
    .line 8
    iget v1, v0, Lf40/t0;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lf40/t0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lf40/t0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lf40/t0;-><init>(Lf40/u0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lf40/t0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lf40/t0;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_4

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Lf40/t0;->f:I

    .line 59
    .line 60
    iget-object p0, p0, Lf40/u0;->a:Lf40/u;

    .line 61
    .line 62
    iget-object p1, p0, Lf40/u;->b:Lf40/c1;

    .line 63
    .line 64
    check-cast p1, Ld40/e;

    .line 65
    .line 66
    iget-object p1, p1, Ld40/e;->f:Lg40/i0;

    .line 67
    .line 68
    if-eqz p1, :cond_4

    .line 69
    .line 70
    new-instance p0, Lne0/e;

    .line 71
    .line 72
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    new-instance p1, Lyy0/m;

    .line 76
    .line 77
    const/4 v2, 0x0

    .line 78
    invoke-direct {p1, p0, v2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_4
    iget-object p1, p0, Lf40/u;->a:Ld40/n;

    .line 83
    .line 84
    iget-object v2, p1, Ld40/n;->a:Lxl0/f;

    .line 85
    .line 86
    new-instance v4, La90/s;

    .line 87
    .line 88
    const/4 v5, 0x5

    .line 89
    const/4 v6, 0x0

    .line 90
    invoke-direct {v4, p1, v6, v5}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 91
    .line 92
    .line 93
    new-instance p1, Lck/b;

    .line 94
    .line 95
    const/16 v5, 0xe

    .line 96
    .line 97
    invoke-direct {p1, v5}, Lck/b;-><init>(I)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v2, v4, p1, v6}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    new-instance v2, Le30/p;

    .line 105
    .line 106
    const/16 v4, 0x9

    .line 107
    .line 108
    invoke-direct {v2, p0, v6, v4}, Le30/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 109
    .line 110
    .line 111
    new-instance p0, Lne0/n;

    .line 112
    .line 113
    const/4 v4, 0x5

    .line 114
    invoke-direct {p0, p1, v2, v4}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 115
    .line 116
    .line 117
    move-object p1, p0

    .line 118
    :goto_1
    if-ne p1, v1, :cond_5

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_5
    :goto_2
    check-cast p1, Lyy0/i;

    .line 122
    .line 123
    invoke-static {p1}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    iput v3, v0, Lf40/t0;->f:I

    .line 128
    .line 129
    invoke-static {p0, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    if-ne p1, v1, :cond_6

    .line 134
    .line 135
    :goto_3
    return-object v1

    .line 136
    :cond_6
    :goto_4
    instance-of p0, p1, Lne0/e;

    .line 137
    .line 138
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    return-object p0
.end method
