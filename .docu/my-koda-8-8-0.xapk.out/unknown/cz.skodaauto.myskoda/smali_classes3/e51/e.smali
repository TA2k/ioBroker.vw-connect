.class public final Le51/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lzv0/c;

.field public final b:Ly41/g;


# direct methods
.method public synthetic constructor <init>(Lzv0/c;Ly41/g;)V
    .locals 0

    .line 1
    iput-object p1, p0, Le51/e;->a:Lzv0/c;

    .line 2
    .line 3
    iput-object p2, p0, Le51/e;->b:Ly41/g;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Le51/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Le51/d;

    .line 7
    .line 8
    iget v1, v0, Le51/d;->f:I

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
    iput v1, v0, Le51/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Le51/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Le51/d;-><init>(Le51/e;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Le51/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Le51/d;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x2

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v3, :cond_2

    .line 36
    .line 37
    if-ne v2, v4, :cond_1

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    check-cast p2, Llx0/o;

    .line 55
    .line 56
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    new-instance p2, Laa/z;

    .line 63
    .line 64
    const/16 v2, 0x19

    .line 65
    .line 66
    invoke-direct {p2, v2, p0, p1}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 70
    .line 71
    const-class v2, Le51/c;

    .line 72
    .line 73
    invoke-virtual {p1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    const/4 v5, 0x0

    .line 78
    :try_start_0
    invoke-static {v2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 79
    .line 80
    .line 81
    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 82
    goto :goto_1

    .line 83
    :catchall_0
    move-object v2, v5

    .line 84
    :goto_1
    new-instance v6, Lzw0/a;

    .line 85
    .line 86
    invoke-direct {v6, p1, v2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 87
    .line 88
    .line 89
    new-instance p1, Lal0/m0;

    .line 90
    .line 91
    const/4 v2, 0x1

    .line 92
    invoke-direct {p1, v4, v5, v2}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 93
    .line 94
    .line 95
    iput v3, v0, Le51/d;->f:I

    .line 96
    .line 97
    iget-object p0, p0, Le51/e;->a:Lzv0/c;

    .line 98
    .line 99
    invoke-static {p0, v6, p2, p1, v0}, Lkp/h7;->i(Lzv0/c;Lzw0/a;Lay0/k;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    if-ne p0, v1, :cond_4

    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_4
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    if-nez p1, :cond_5

    .line 111
    .line 112
    check-cast p0, Le51/c;

    .line 113
    .line 114
    iget-object p0, p0, Le51/c;->a:Le51/h;

    .line 115
    .line 116
    goto :goto_5

    .line 117
    :cond_5
    check-cast p1, Ls51/b;

    .line 118
    .line 119
    iput v4, v0, Le51/d;->f:I

    .line 120
    .line 121
    invoke-static {p1, v0}, Lim/g;->h(Ls51/b;Lrx0/c;)Ljava/io/Serializable;

    .line 122
    .line 123
    .line 124
    move-result-object p2

    .line 125
    if-ne p2, v1, :cond_6

    .line 126
    .line 127
    :goto_3
    return-object v1

    .line 128
    :cond_6
    :goto_4
    check-cast p2, Ljava/lang/Throwable;

    .line 129
    .line 130
    invoke-static {p2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    :goto_5
    return-object p0
.end method

.method public b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lf51/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lf51/g;

    .line 7
    .line 8
    iget v1, v0, Lf51/g;->f:I

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
    iput v1, v0, Lf51/g;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lf51/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lf51/g;-><init>(Le51/e;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lf51/g;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lf51/g;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x2

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v3, :cond_2

    .line 36
    .line 37
    if-ne v2, v4, :cond_1

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    check-cast p2, Llx0/o;

    .line 55
    .line 56
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    new-instance p2, Let/g;

    .line 63
    .line 64
    const/4 v2, 0x2

    .line 65
    invoke-direct {p2, v2, p0, p1}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 69
    .line 70
    const-class v2, Lf51/c;

    .line 71
    .line 72
    invoke-virtual {p1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    const/4 v5, 0x0

    .line 77
    :try_start_0
    invoke-static {v2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 78
    .line 79
    .line 80
    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 81
    goto :goto_1

    .line 82
    :catchall_0
    move-object v2, v5

    .line 83
    :goto_1
    new-instance v6, Lzw0/a;

    .line 84
    .line 85
    invoke-direct {v6, p1, v2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 86
    .line 87
    .line 88
    new-instance p1, Lal0/m0;

    .line 89
    .line 90
    const/4 v2, 0x2

    .line 91
    invoke-direct {p1, v4, v5, v2}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 92
    .line 93
    .line 94
    iput v3, v0, Lf51/g;->f:I

    .line 95
    .line 96
    iget-object p0, p0, Le51/e;->a:Lzv0/c;

    .line 97
    .line 98
    invoke-static {p0, v6, p2, p1, v0}, Lkp/h7;->i(Lzv0/c;Lzw0/a;Lay0/k;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    if-ne p0, v1, :cond_4

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_4
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    if-nez p1, :cond_5

    .line 110
    .line 111
    check-cast p0, Lf51/c;

    .line 112
    .line 113
    iget-object p0, p0, Lf51/c;->a:Lf51/f;

    .line 114
    .line 115
    goto :goto_5

    .line 116
    :cond_5
    check-cast p1, Ls51/b;

    .line 117
    .line 118
    iput v4, v0, Lf51/g;->f:I

    .line 119
    .line 120
    invoke-static {p1, v0}, Lim/g;->h(Ls51/b;Lrx0/c;)Ljava/io/Serializable;

    .line 121
    .line 122
    .line 123
    move-result-object p2

    .line 124
    if-ne p2, v1, :cond_6

    .line 125
    .line 126
    :goto_3
    return-object v1

    .line 127
    :cond_6
    :goto_4
    check-cast p2, Ljava/lang/Throwable;

    .line 128
    .line 129
    invoke-static {p2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    :goto_5
    return-object p0
.end method
