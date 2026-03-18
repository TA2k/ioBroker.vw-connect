.class public final Len0/c;
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
    iput-object p1, p0, Len0/c;->a:Lla/u;

    .line 5
    .line 6
    new-instance p1, Las0/h;

    .line 7
    .line 8
    const/4 v0, 0x3

    .line 9
    invoke-direct {p1, p0, v0}, Las0/h;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Len0/c;->b:Las0/h;

    .line 13
    .line 14
    return-void
.end method

.method public static a(Len0/c;Ljava/lang/String;Ljava/util/List;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p3, Len0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Len0/b;

    .line 7
    .line 8
    iget v1, v0, Len0/b;->h:I

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
    iput v1, v0, Len0/b;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Len0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Len0/b;-><init>(Len0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Len0/b;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Len0/b;->h:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v6, :cond_2

    .line 39
    .line 40
    if-ne v2, v4, :cond_1

    .line 41
    .line 42
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-object v5

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
    iget-object p0, v0, Len0/b;->e:Ljava/lang/Object;

    .line 55
    .line 56
    move-object p2, p0

    .line 57
    check-cast p2, Ljava/util/List;

    .line 58
    .line 59
    iget-object p0, v0, Len0/b;->d:Len0/c;

    .line 60
    .line 61
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iput-object p0, v0, Len0/b;->d:Len0/c;

    .line 69
    .line 70
    iput-object p2, v0, Len0/b;->e:Ljava/lang/Object;

    .line 71
    .line 72
    iput v6, v0, Len0/b;->h:I

    .line 73
    .line 74
    iget-object p3, p0, Len0/c;->a:Lla/u;

    .line 75
    .line 76
    new-instance v2, Lac0/r;

    .line 77
    .line 78
    const/4 v7, 0x7

    .line 79
    invoke-direct {v2, p1, v7}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 80
    .line 81
    .line 82
    invoke-static {v0, p3, v3, v6, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    if-ne p1, v1, :cond_4

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_4
    move-object p1, v5

    .line 90
    :goto_1
    if-ne p1, v1, :cond_5

    .line 91
    .line 92
    goto :goto_4

    .line 93
    :cond_5
    :goto_2
    const/4 p1, 0x0

    .line 94
    iput-object p1, v0, Len0/b;->d:Len0/c;

    .line 95
    .line 96
    iput-object p1, v0, Len0/b;->e:Ljava/lang/Object;

    .line 97
    .line 98
    iput v4, v0, Len0/b;->h:I

    .line 99
    .line 100
    iget-object p1, p0, Len0/c;->a:Lla/u;

    .line 101
    .line 102
    new-instance p3, Laa/z;

    .line 103
    .line 104
    const/16 v2, 0x1b

    .line 105
    .line 106
    invoke-direct {p3, v2, p0, p2}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    invoke-static {v0, p1, v3, v6, p3}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    if-ne p0, v1, :cond_6

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_6
    move-object p0, v5

    .line 117
    :goto_3
    if-ne p0, v1, :cond_7

    .line 118
    .line 119
    :goto_4
    return-object v1

    .line 120
    :cond_7
    return-object v5
.end method
