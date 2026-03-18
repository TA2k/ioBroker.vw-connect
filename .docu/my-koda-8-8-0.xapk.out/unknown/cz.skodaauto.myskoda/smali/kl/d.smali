.class public final Lkl/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lkl/l;

.field public final b:Ltl/l;

.field public final c:Lez0/e;

.field public final d:Lkl/h;


# direct methods
.method public constructor <init>(Lkl/l;Ltl/l;Lez0/e;Lkl/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkl/d;->a:Lkl/l;

    .line 5
    .line 6
    iput-object p2, p0, Lkl/d;->b:Ltl/l;

    .line 7
    .line 8
    iput-object p3, p0, Lkl/d;->c:Lez0/e;

    .line 9
    .line 10
    iput-object p4, p0, Lkl/d;->d:Lkl/h;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lkl/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lkl/c;

    .line 7
    .line 8
    iget v1, v0, Lkl/c;->h:I

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
    iput v1, v0, Lkl/c;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkl/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lkl/c;-><init>(Lkl/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lkl/c;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkl/c;->h:I

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
    iget-object p0, v0, Lkl/c;->d:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Lez0/e;

    .line 42
    .line 43
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :catchall_0
    move-exception p1

    .line 48
    goto :goto_5

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-object p0, v0, Lkl/c;->e:Lez0/e;

    .line 58
    .line 59
    iget-object v2, v0, Lkl/c;->d:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v2, Lkl/d;

    .line 62
    .line 63
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    move-object p1, p0

    .line 67
    move-object p0, v2

    .line 68
    goto :goto_1

    .line 69
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iput-object p0, v0, Lkl/c;->d:Ljava/lang/Object;

    .line 73
    .line 74
    iget-object p1, p0, Lkl/d;->c:Lez0/e;

    .line 75
    .line 76
    iput-object p1, v0, Lkl/c;->e:Lez0/e;

    .line 77
    .line 78
    iput v4, v0, Lkl/c;->h:I

    .line 79
    .line 80
    move-object v2, p1

    .line 81
    check-cast v2, Lez0/h;

    .line 82
    .line 83
    invoke-virtual {v2, v0}, Lez0/h;->c(Lrx0/c;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    if-ne v2, v1, :cond_4

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_4
    :goto_1
    :try_start_1
    new-instance v2, La7/j;

    .line 91
    .line 92
    const/16 v4, 0x9

    .line 93
    .line 94
    invoke-direct {v2, p0, v4}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 95
    .line 96
    .line 97
    iput-object p1, v0, Lkl/c;->d:Ljava/lang/Object;

    .line 98
    .line 99
    const/4 p0, 0x0

    .line 100
    iput-object p0, v0, Lkl/c;->e:Lez0/e;

    .line 101
    .line 102
    iput v3, v0, Lkl/c;->h:I

    .line 103
    .line 104
    sget-object v3, Lpx0/h;->d:Lpx0/h;

    .line 105
    .line 106
    new-instance v4, Ls10/a0;

    .line 107
    .line 108
    const/16 v5, 0x15

    .line 109
    .line 110
    invoke-direct {v4, v2, p0, v5}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 111
    .line 112
    .line 113
    invoke-static {v3, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 117
    if-ne p0, v1, :cond_5

    .line 118
    .line 119
    :goto_2
    return-object v1

    .line 120
    :cond_5
    move-object v6, p1

    .line 121
    move-object p1, p0

    .line 122
    move-object p0, v6

    .line 123
    :goto_3
    :try_start_2
    check-cast p1, Lkl/f;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 124
    .line 125
    check-cast p0, Lez0/h;

    .line 126
    .line 127
    invoke-virtual {p0}, Lez0/h;->f()V

    .line 128
    .line 129
    .line 130
    return-object p1

    .line 131
    :goto_4
    move-object v6, p1

    .line 132
    move-object p1, p0

    .line 133
    move-object p0, v6

    .line 134
    goto :goto_5

    .line 135
    :catchall_1
    move-exception p0

    .line 136
    goto :goto_4

    .line 137
    :goto_5
    check-cast p0, Lez0/h;

    .line 138
    .line 139
    invoke-virtual {p0}, Lez0/h;->f()V

    .line 140
    .line 141
    .line 142
    throw p1
.end method
