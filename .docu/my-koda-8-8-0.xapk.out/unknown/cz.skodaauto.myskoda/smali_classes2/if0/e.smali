.class public final Lif0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;

.field public final b:Las0/h;


# direct methods
.method public constructor <init>(Lla/u;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lif0/e;->a:Lla/u;

    .line 5
    .line 6
    new-instance p1, Las0/h;

    .line 7
    .line 8
    const/16 v0, 0x9

    .line 9
    .line 10
    invoke-direct {p1, p0, v0}, Las0/h;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lif0/e;->b:Las0/h;

    .line 14
    .line 15
    return-void
.end method

.method public static a(Lif0/e;Ljava/lang/String;Ljava/util/ArrayList;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p3, Lif0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lif0/c;

    .line 7
    .line 8
    iget v1, v0, Lif0/c;->h:I

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
    iput v1, v0, Lif0/c;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lif0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lif0/c;-><init>(Lif0/e;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lif0/c;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lif0/c;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v6, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-object v4

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    iget-object p2, v0, Lif0/c;->e:Ljava/util/ArrayList;

    .line 55
    .line 56
    iget-object p0, v0, Lif0/c;->d:Lif0/e;

    .line 57
    .line 58
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iput-object p0, v0, Lif0/c;->d:Lif0/e;

    .line 66
    .line 67
    iput-object p2, v0, Lif0/c;->e:Ljava/util/ArrayList;

    .line 68
    .line 69
    iput v6, v0, Lif0/c;->h:I

    .line 70
    .line 71
    iget-object p3, p0, Lif0/e;->a:Lla/u;

    .line 72
    .line 73
    new-instance v2, Lif0/d;

    .line 74
    .line 75
    const/4 v7, 0x0

    .line 76
    invoke-direct {v2, p1, v7}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    invoke-static {v0, p3, v5, v6, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    if-ne p1, v1, :cond_4

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_4
    move-object p1, v4

    .line 87
    :goto_1
    if-ne p1, v1, :cond_5

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_5
    :goto_2
    if-eqz p2, :cond_7

    .line 91
    .line 92
    const/4 p1, 0x0

    .line 93
    iput-object p1, v0, Lif0/c;->d:Lif0/e;

    .line 94
    .line 95
    iput-object p1, v0, Lif0/c;->e:Ljava/util/ArrayList;

    .line 96
    .line 97
    iput v3, v0, Lif0/c;->h:I

    .line 98
    .line 99
    iget-object p1, p0, Lif0/e;->a:Lla/u;

    .line 100
    .line 101
    new-instance p3, Li40/j0;

    .line 102
    .line 103
    const/16 v2, 0x9

    .line 104
    .line 105
    invoke-direct {p3, v2, p0, p2}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    invoke-static {v0, p1, v5, v6, p3}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    if-ne p0, v1, :cond_6

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_6
    move-object p0, v4

    .line 116
    :goto_3
    if-ne p0, v1, :cond_7

    .line 117
    .line 118
    :goto_4
    return-object v1

    .line 119
    :cond_7
    return-object v4
.end method
