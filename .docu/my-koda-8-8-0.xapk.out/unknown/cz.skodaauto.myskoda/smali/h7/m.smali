.class public final Lh7/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh7/h;


# instance fields
.field public final a:Lez0/c;

.field public final b:Lh7/l;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lh7/m;->a:Lez0/c;

    .line 9
    .line 10
    new-instance v0, Lh7/l;

    .line 11
    .line 12
    invoke-direct {v0, p0}, Lh7/l;-><init>(Lh7/m;)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lh7/m;->b:Lh7/l;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lh7/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lh7/i;

    .line 7
    .line 8
    iget v1, v0, Lh7/i;->i:I

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
    iput v1, v0, Lh7/i;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh7/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lh7/i;-><init>(Lh7/m;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lh7/i;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh7/i;->i:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    iget-object p0, v0, Lh7/i;->d:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Lez0/a;

    .line 43
    .line 44
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    goto :goto_3

    .line 48
    :catchall_0
    move-exception p1

    .line 49
    goto :goto_4

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    iget-object p0, v0, Lh7/i;->f:Lez0/c;

    .line 59
    .line 60
    iget-object p1, v0, Lh7/i;->e:Lrx0/i;

    .line 61
    .line 62
    check-cast p1, Lay0/n;

    .line 63
    .line 64
    iget-object v2, v0, Lh7/i;->d:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v2, Lh7/m;

    .line 67
    .line 68
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    move-object p2, p0

    .line 72
    move-object p0, v2

    .line 73
    goto :goto_1

    .line 74
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iput-object p0, v0, Lh7/i;->d:Ljava/lang/Object;

    .line 78
    .line 79
    move-object p2, p1

    .line 80
    check-cast p2, Lrx0/i;

    .line 81
    .line 82
    iput-object p2, v0, Lh7/i;->e:Lrx0/i;

    .line 83
    .line 84
    iget-object p2, p0, Lh7/m;->a:Lez0/c;

    .line 85
    .line 86
    iput-object p2, v0, Lh7/i;->f:Lez0/c;

    .line 87
    .line 88
    iput v4, v0, Lh7/i;->i:I

    .line 89
    .line 90
    invoke-virtual {p2, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    if-ne v2, v1, :cond_4

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_4
    :goto_1
    :try_start_1
    iget-object p0, p0, Lh7/m;->b:Lh7/l;

    .line 98
    .line 99
    iput-object p2, v0, Lh7/i;->d:Ljava/lang/Object;

    .line 100
    .line 101
    iput-object v5, v0, Lh7/i;->e:Lrx0/i;

    .line 102
    .line 103
    iput-object v5, v0, Lh7/i;->f:Lez0/c;

    .line 104
    .line 105
    iput v3, v0, Lh7/i;->i:I

    .line 106
    .line 107
    invoke-interface {p1, p0, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 111
    if-ne p0, v1, :cond_5

    .line 112
    .line 113
    :goto_2
    return-object v1

    .line 114
    :cond_5
    move-object v6, p2

    .line 115
    move-object p2, p0

    .line 116
    move-object p0, v6

    .line 117
    :goto_3
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    return-object p2

    .line 121
    :catchall_1
    move-exception p1

    .line 122
    move-object p0, p2

    .line 123
    :goto_4
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    throw p1
.end method
