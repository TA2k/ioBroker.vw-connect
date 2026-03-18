.class public final Lh2/aa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lez0/c;

.field public final b:Ll2/j1;


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
    iput-object v0, p0, Lh2/aa;->a:Lez0/c;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lh2/aa;->b:Ll2/j1;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(Lh2/y9;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lh2/z9;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lh2/z9;

    .line 7
    .line 8
    iget v1, v0, Lh2/z9;->h:I

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
    iput v1, v0, Lh2/z9;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh2/z9;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lh2/z9;-><init>(Lh2/aa;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lh2/z9;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh2/z9;->h:I

    .line 30
    .line 31
    iget-object v3, p0, Lh2/aa;->b:Ll2/j1;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    const/4 v6, 0x0

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v5, :cond_2

    .line 39
    .line 40
    if-ne v2, v4, :cond_1

    .line 41
    .line 42
    iget-object p0, v0, Lh2/z9;->e:Lez0/a;

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
    iget-object p0, v0, Lh2/z9;->e:Lez0/a;

    .line 59
    .line 60
    iget-object p1, v0, Lh2/z9;->d:Lh2/y9;

    .line 61
    .line 62
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iput-object p1, v0, Lh2/z9;->d:Lh2/y9;

    .line 70
    .line 71
    iget-object p0, p0, Lh2/aa;->a:Lez0/c;

    .line 72
    .line 73
    iput-object p0, v0, Lh2/z9;->e:Lez0/a;

    .line 74
    .line 75
    iput v5, v0, Lh2/z9;->h:I

    .line 76
    .line 77
    invoke-virtual {p0, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    if-ne p2, v1, :cond_4

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_4
    :goto_1
    :try_start_1
    iput-object p1, v0, Lh2/z9;->d:Lh2/y9;

    .line 85
    .line 86
    iput-object p0, v0, Lh2/z9;->e:Lez0/a;

    .line 87
    .line 88
    iput v4, v0, Lh2/z9;->h:I

    .line 89
    .line 90
    new-instance p2, Lvy0/l;

    .line 91
    .line 92
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    invoke-direct {p2, v5, v0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p2}, Lvy0/l;->q()V

    .line 100
    .line 101
    .line 102
    new-instance v0, Lh2/x9;

    .line 103
    .line 104
    invoke-direct {v0, p1, p2}, Lh2/x9;-><init>(Lh2/y9;Lvy0/l;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v3, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 114
    if-ne p2, v1, :cond_5

    .line 115
    .line 116
    :goto_2
    return-object v1

    .line 117
    :cond_5
    :goto_3
    :try_start_2
    invoke-virtual {v3, v6}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 118
    .line 119
    .line 120
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    return-object p2

    .line 124
    :catchall_1
    move-exception p1

    .line 125
    goto :goto_5

    .line 126
    :goto_4
    :try_start_3
    invoke-virtual {v3, v6}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 130
    :goto_5
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    throw p1
.end method
