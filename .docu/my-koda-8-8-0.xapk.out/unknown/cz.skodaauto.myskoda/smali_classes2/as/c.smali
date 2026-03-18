.class public final synthetic Las/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/b;
.implements Laq/i;


# instance fields
.field public final synthetic d:Las/d;


# direct methods
.method public synthetic constructor <init>(Las/d;)V
    .locals 0

    .line 1
    iput-object p1, p0, Las/c;->d:Las/d;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public g(Ljava/lang/Object;)Laq/t;
    .locals 10

    .line 1
    iget-object p0, p0, Las/c;->d:Las/d;

    .line 2
    .line 3
    check-cast p1, Las/b;

    .line 4
    .line 5
    iget-object v0, p0, Las/d;->i:Ljava/util/concurrent/Executor;

    .line 6
    .line 7
    new-instance v1, La8/z;

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    invoke-direct {v1, v2, p0, p1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Las/d;->m:Las/b;

    .line 17
    .line 18
    iget-object v0, p0, Las/d;->f:Las/i;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    instance-of v1, p1, Las/b;

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    move-object v1, p1

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    iget-object v1, p1, Las/b;->a:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v1}, Las/b;->a(Ljava/lang/String;)Las/b;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    :goto_0
    iget-wide v2, v1, Las/b;->b:J

    .line 36
    .line 37
    iget-wide v4, v1, Las/b;->c:J

    .line 38
    .line 39
    long-to-double v4, v4

    .line 40
    const-wide/high16 v6, 0x3fe0000000000000L    # 0.5

    .line 41
    .line 42
    mul-double/2addr v4, v6

    .line 43
    double-to-long v4, v4

    .line 44
    add-long/2addr v2, v4

    .line 45
    const-wide/32 v4, 0x493e0

    .line 46
    .line 47
    .line 48
    add-long/2addr v2, v4

    .line 49
    iput-wide v2, v0, Las/i;->a:J

    .line 50
    .line 51
    iget-wide v2, v0, Las/i;->a:J

    .line 52
    .line 53
    iget-wide v4, v1, Las/b;->b:J

    .line 54
    .line 55
    iget-wide v6, v1, Las/b;->c:J

    .line 56
    .line 57
    add-long v8, v4, v6

    .line 58
    .line 59
    cmp-long v1, v2, v8

    .line 60
    .line 61
    if-lez v1, :cond_1

    .line 62
    .line 63
    add-long/2addr v4, v6

    .line 64
    const-wide/32 v1, 0xea60

    .line 65
    .line 66
    .line 67
    sub-long/2addr v4, v1

    .line 68
    iput-wide v4, v0, Las/i;->a:J

    .line 69
    .line 70
    :cond_1
    iget-object v0, p0, Las/d;->d:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    if-nez v1, :cond_3

    .line 81
    .line 82
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iget-object v0, p1, Las/b;->a:Ljava/lang/String;

    .line 86
    .line 87
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    iget-object p0, p0, Las/d;->c:Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-nez v0, :cond_2

    .line 101
    .line 102
    invoke-static {p1}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0

    .line 107
    :cond_2
    invoke-static {p0}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    throw p0

    .line 112
    :cond_3
    invoke-static {v0}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    throw p0
.end method

.method public w(Laq/j;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object p0, p0, Las/c;->d:Las/d;

    .line 2
    .line 3
    iget-object p1, p0, Las/d;->m:Las/b;

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    iget-wide v0, p1, Las/b;->b:J

    .line 8
    .line 9
    iget-wide v2, p1, Las/b;->c:J

    .line 10
    .line 11
    add-long/2addr v0, v2

    .line 12
    iget-object p1, p0, Las/d;->k:Lrb0/a;

    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 18
    .line 19
    .line 20
    move-result-wide v2

    .line 21
    sub-long/2addr v0, v2

    .line 22
    const-wide/32 v2, 0x493e0

    .line 23
    .line 24
    .line 25
    cmp-long p1, v0, v2

    .line 26
    .line 27
    if-lez p1, :cond_0

    .line 28
    .line 29
    iget-object p0, p0, Las/d;->m:Las/b;

    .line 30
    .line 31
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :cond_0
    iget-object p1, p0, Las/d;->l:Les/d;

    .line 37
    .line 38
    if-nez p1, :cond_1

    .line 39
    .line 40
    new-instance p0, Lsr/h;

    .line 41
    .line 42
    const-string p1, "No AppCheckProvider installed."

    .line 43
    .line 44
    invoke-direct {p0, p1}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0

    .line 52
    :cond_1
    iget-object p1, p0, Las/d;->n:Laq/t;

    .line 53
    .line 54
    if-eqz p1, :cond_2

    .line 55
    .line 56
    invoke-virtual {p1}, Laq/t;->h()Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-nez p1, :cond_2

    .line 61
    .line 62
    iget-object p1, p0, Las/d;->n:Laq/t;

    .line 63
    .line 64
    iget-boolean p1, p1, Laq/t;->d:Z

    .line 65
    .line 66
    if-eqz p1, :cond_3

    .line 67
    .line 68
    :cond_2
    iget-object p1, p0, Las/d;->l:Les/d;

    .line 69
    .line 70
    new-instance v0, Lwq/f;

    .line 71
    .line 72
    const/4 v1, 0x4

    .line 73
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 74
    .line 75
    .line 76
    iget-object v1, p1, Les/d;->e:Ljava/util/concurrent/Executor;

    .line 77
    .line 78
    new-instance v2, Lbm/x;

    .line 79
    .line 80
    invoke-direct {v2, p1, v0}, Lbm/x;-><init>(Les/d;Lwq/f;)V

    .line 81
    .line 82
    .line 83
    invoke-static {v1, v2}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    iget-object v1, p1, Les/d;->d:Ljava/util/concurrent/Executor;

    .line 88
    .line 89
    new-instance v2, Les/c;

    .line 90
    .line 91
    const/4 v3, 0x1

    .line 92
    invoke-direct {v2, p1, v3}, Les/c;-><init>(Les/d;I)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v0, v1, v2}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    new-instance v2, Les/c;

    .line 100
    .line 101
    const/4 v3, 0x0

    .line 102
    invoke-direct {v2, p1, v3}, Les/c;-><init>(Les/d;I)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0, v1, v2}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    new-instance v0, Lc1/y;

    .line 110
    .line 111
    const/16 v2, 0x1a

    .line 112
    .line 113
    invoke-direct {v0, v2}, Lc1/y;-><init>(I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1, v1, v0}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    iget-object v0, p0, Las/d;->g:Ljava/util/concurrent/Executor;

    .line 121
    .line 122
    new-instance v1, Las/c;

    .line 123
    .line 124
    invoke-direct {v1, p0}, Las/c;-><init>(Las/d;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p1, v0, v1}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    iput-object p1, p0, Las/d;->n:Laq/t;

    .line 132
    .line 133
    :cond_3
    iget-object p0, p0, Las/d;->n:Laq/t;

    .line 134
    .line 135
    return-object p0
.end method
