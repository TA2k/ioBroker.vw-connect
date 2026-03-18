.class public final Lrn0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltn0/f;


# instance fields
.field public final a:Lyy0/q1;

.field public final b:Lyy0/k1;

.field public final c:Lyy0/q1;

.field public final d:Lyy0/c2;

.field public final e:Lag/r;

.field public final f:Lyy0/q1;

.field public final g:Lyy0/k1;

.field public final h:Lez0/c;


# direct methods
.method public constructor <init>()V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x5

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-static {v0, v0, v1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    iput-object v2, p0, Lrn0/i;->a:Lyy0/q1;

    .line 11
    .line 12
    new-instance v3, Lyy0/k1;

    .line 13
    .line 14
    invoke-direct {v3, v2}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 15
    .line 16
    .line 17
    iput-object v3, p0, Lrn0/i;->b:Lyy0/k1;

    .line 18
    .line 19
    invoke-static {v0, v0, v1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    iput-object v2, p0, Lrn0/i;->c:Lyy0/q1;

    .line 24
    .line 25
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 26
    .line 27
    invoke-static {v2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    iput-object v2, p0, Lrn0/i;->d:Lyy0/c2;

    .line 32
    .line 33
    new-instance v3, Lag/r;

    .line 34
    .line 35
    const/16 v4, 0xd

    .line 36
    .line 37
    invoke-direct {v3, v2, v4}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 38
    .line 39
    .line 40
    iput-object v3, p0, Lrn0/i;->e:Lag/r;

    .line 41
    .line 42
    const/4 v2, 0x1

    .line 43
    invoke-static {v2, v0, v1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iput-object v0, p0, Lrn0/i;->f:Lyy0/q1;

    .line 48
    .line 49
    new-instance v1, Lyy0/k1;

    .line 50
    .line 51
    invoke-direct {v1, v0}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 52
    .line 53
    .line 54
    iput-object v1, p0, Lrn0/i;->g:Lyy0/k1;

    .line 55
    .line 56
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    iput-object v0, p0, Lrn0/i;->h:Lez0/c;

    .line 61
    .line 62
    return-void
.end method


# virtual methods
.method public final a(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Lrn0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lrn0/a;

    .line 7
    .line 8
    iget v1, v0, Lrn0/a;->i:I

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
    iput v1, v0, Lrn0/a;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lrn0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lrn0/a;-><init>(Lrn0/i;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lrn0/a;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lrn0/a;->i:I

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
    iget-object p0, v0, Lrn0/a;->e:Lez0/a;

    .line 41
    .line 42
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    goto :goto_3

    .line 46
    :catchall_0
    move-exception p1

    .line 47
    goto :goto_5

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget p1, v0, Lrn0/a;->f:I

    .line 57
    .line 58
    iget-object v2, v0, Lrn0/a;->e:Lez0/a;

    .line 59
    .line 60
    iget-object v4, v0, Lrn0/a;->d:Lun0/a;

    .line 61
    .line 62
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move-object p2, v2

    .line 66
    move v2, p1

    .line 67
    move-object p1, v4

    .line 68
    goto :goto_1

    .line 69
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iput-object p1, v0, Lrn0/a;->d:Lun0/a;

    .line 73
    .line 74
    iget-object p2, p0, Lrn0/i;->h:Lez0/c;

    .line 75
    .line 76
    iput-object p2, v0, Lrn0/a;->e:Lez0/a;

    .line 77
    .line 78
    const/4 v2, 0x0

    .line 79
    iput v2, v0, Lrn0/a;->f:I

    .line 80
    .line 81
    iput v4, v0, Lrn0/a;->i:I

    .line 82
    .line 83
    invoke-virtual {p2, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    if-ne v4, v1, :cond_4

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_4
    :goto_1
    :try_start_1
    iget-object v4, p0, Lrn0/i;->c:Lyy0/q1;

    .line 91
    .line 92
    new-instance v6, Lrn0/b;

    .line 93
    .line 94
    const/4 v7, 0x0

    .line 95
    invoke-direct {v6, p0, p1, v5, v7}, Lrn0/b;-><init>(Lrn0/i;Lun0/a;Lkotlin/coroutines/Continuation;I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 96
    .line 97
    .line 98
    :try_start_2
    new-instance p0, Lyy0/h2;

    .line 99
    .line 100
    invoke-direct {p0, v4, v6}, Lyy0/h2;-><init>(Lyy0/n1;Lay0/n;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 101
    .line 102
    .line 103
    :try_start_3
    new-instance v4, Lrn0/e;

    .line 104
    .line 105
    const/4 v6, 0x0

    .line 106
    invoke-direct {v4, p0, p1, v6}, Lrn0/e;-><init>(Lyy0/h2;Lun0/a;I)V

    .line 107
    .line 108
    .line 109
    iput-object v5, v0, Lrn0/a;->d:Lun0/a;

    .line 110
    .line 111
    iput-object p2, v0, Lrn0/a;->e:Lez0/a;

    .line 112
    .line 113
    iput v2, v0, Lrn0/a;->f:I

    .line 114
    .line 115
    iput v3, v0, Lrn0/a;->i:I

    .line 116
    .line 117
    invoke-static {v4, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 121
    if-ne p0, v1, :cond_5

    .line 122
    .line 123
    :goto_2
    return-object v1

    .line 124
    :cond_5
    move-object v8, p2

    .line 125
    move-object p2, p0

    .line 126
    move-object p0, v8

    .line 127
    :goto_3
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    return-object p2

    .line 131
    :catchall_1
    move-exception p1

    .line 132
    :goto_4
    move-object p0, p2

    .line 133
    goto :goto_5

    .line 134
    :catchall_2
    move-exception p0

    .line 135
    move-object p1, p0

    .line 136
    goto :goto_4

    .line 137
    :goto_5
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    throw p1
.end method

.method public final b(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Lrn0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lrn0/f;

    .line 7
    .line 8
    iget v1, v0, Lrn0/f;->i:I

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
    iput v1, v0, Lrn0/f;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lrn0/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lrn0/f;-><init>(Lrn0/i;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lrn0/f;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lrn0/f;->i:I

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
    iget-object p0, v0, Lrn0/f;->e:Lez0/a;

    .line 41
    .line 42
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    goto :goto_3

    .line 46
    :catchall_0
    move-exception p1

    .line 47
    goto :goto_5

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget p1, v0, Lrn0/f;->f:I

    .line 57
    .line 58
    iget-object v2, v0, Lrn0/f;->e:Lez0/a;

    .line 59
    .line 60
    iget-object v4, v0, Lrn0/f;->d:Lun0/a;

    .line 61
    .line 62
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move-object p2, v2

    .line 66
    move v2, p1

    .line 67
    move-object p1, v4

    .line 68
    goto :goto_1

    .line 69
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iput-object p1, v0, Lrn0/f;->d:Lun0/a;

    .line 73
    .line 74
    iget-object p2, p0, Lrn0/i;->h:Lez0/c;

    .line 75
    .line 76
    iput-object p2, v0, Lrn0/f;->e:Lez0/a;

    .line 77
    .line 78
    const/4 v2, 0x0

    .line 79
    iput v2, v0, Lrn0/f;->f:I

    .line 80
    .line 81
    iput v4, v0, Lrn0/f;->i:I

    .line 82
    .line 83
    invoke-virtual {p2, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    if-ne v4, v1, :cond_4

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_4
    :goto_1
    :try_start_1
    iget-object v4, p0, Lrn0/i;->c:Lyy0/q1;

    .line 91
    .line 92
    new-instance v6, Lrn0/b;

    .line 93
    .line 94
    const/4 v7, 0x1

    .line 95
    invoke-direct {v6, p0, p1, v5, v7}, Lrn0/b;-><init>(Lrn0/i;Lun0/a;Lkotlin/coroutines/Continuation;I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 96
    .line 97
    .line 98
    :try_start_2
    new-instance p0, Lyy0/h2;

    .line 99
    .line 100
    invoke-direct {p0, v4, v6}, Lyy0/h2;-><init>(Lyy0/n1;Lay0/n;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 101
    .line 102
    .line 103
    :try_start_3
    new-instance v4, Lrn0/e;

    .line 104
    .line 105
    const/4 v6, 0x1

    .line 106
    invoke-direct {v4, p0, p1, v6}, Lrn0/e;-><init>(Lyy0/h2;Lun0/a;I)V

    .line 107
    .line 108
    .line 109
    iput-object v5, v0, Lrn0/f;->d:Lun0/a;

    .line 110
    .line 111
    iput-object p2, v0, Lrn0/f;->e:Lez0/a;

    .line 112
    .line 113
    iput v2, v0, Lrn0/f;->f:I

    .line 114
    .line 115
    iput v3, v0, Lrn0/f;->i:I

    .line 116
    .line 117
    invoke-static {v4, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 121
    if-ne p0, v1, :cond_5

    .line 122
    .line 123
    :goto_2
    return-object v1

    .line 124
    :cond_5
    move-object v8, p2

    .line 125
    move-object p2, p0

    .line 126
    move-object p0, v8

    .line 127
    :goto_3
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    return-object p2

    .line 131
    :catchall_1
    move-exception p1

    .line 132
    :goto_4
    move-object p0, p2

    .line 133
    goto :goto_5

    .line 134
    :catchall_2
    move-exception p0

    .line 135
    move-object p1, p0

    .line 136
    goto :goto_4

    .line 137
    :goto_5
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    throw p1
.end method
