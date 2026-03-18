.class public final Laq/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/r;
.implements Laq/g;
.implements Laq/f;
.implements Laq/d;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/util/concurrent/Executor;

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/Executor;Laq/d;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Laq/q;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Laq/q;->f:Ljava/lang/Object;

    iput-object p1, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    iput-object p2, p0, Laq/q;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/Executor;Laq/e;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Laq/q;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Laq/q;->f:Ljava/lang/Object;

    iput-object p1, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    iput-object p2, p0, Laq/q;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/Executor;Laq/f;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Laq/q;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Laq/q;->f:Ljava/lang/Object;

    iput-object p1, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    iput-object p2, p0, Laq/q;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/Executor;Laq/g;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Laq/q;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Laq/q;->f:Ljava/lang/Object;

    iput-object p1, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    iput-object p2, p0, Laq/q;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/Executor;Laq/i;Laq/t;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Laq/q;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    iput-object p2, p0, Laq/q;->f:Ljava/lang/Object;

    iput-object p3, p0, Laq/q;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a(Laq/j;)V
    .locals 4

    .line 1
    iget v0, p0, Laq/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llr/b;

    .line 7
    .line 8
    const/4 v1, 0x3

    .line 9
    const/4 v2, 0x0

    .line 10
    invoke-direct {v0, p0, p1, v2, v1}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    .line 14
    .line 15
    invoke-interface {p0, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_0
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-object v0, p0, Laq/q;->f:Ljava/lang/Object;

    .line 26
    .line 27
    monitor-enter v0

    .line 28
    :try_start_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    iget-object v0, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    .line 30
    .line 31
    new-instance v1, Lk0/g;

    .line 32
    .line 33
    const/4 v2, 0x3

    .line 34
    const/4 v3, 0x0

    .line 35
    invoke-direct {v1, p0, p1, v3, v2}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 36
    .line 37
    .line 38
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception p0

    .line 43
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 44
    throw p0

    .line 45
    :cond_0
    :goto_0
    return-void

    .line 46
    :pswitch_1
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-nez v0, :cond_1

    .line 51
    .line 52
    move-object v0, p1

    .line 53
    check-cast v0, Laq/t;

    .line 54
    .line 55
    iget-boolean v0, v0, Laq/t;->d:Z

    .line 56
    .line 57
    if-nez v0, :cond_1

    .line 58
    .line 59
    iget-object v0, p0, Laq/q;->f:Ljava/lang/Object;

    .line 60
    .line 61
    monitor-enter v0

    .line 62
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 63
    iget-object v0, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    .line 64
    .line 65
    new-instance v1, Llr/b;

    .line 66
    .line 67
    const/4 v2, 0x2

    .line 68
    const/4 v3, 0x0

    .line 69
    invoke-direct {v1, p0, p1, v3, v2}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 70
    .line 71
    .line 72
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :catchall_1
    move-exception p0

    .line 77
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 78
    throw p0

    .line 79
    :cond_1
    :goto_1
    return-void

    .line 80
    :pswitch_2
    iget-object v0, p0, Laq/q;->f:Ljava/lang/Object;

    .line 81
    .line 82
    monitor-enter v0

    .line 83
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 84
    iget-object v0, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    .line 85
    .line 86
    new-instance v1, Lk0/g;

    .line 87
    .line 88
    const/4 v2, 0x2

    .line 89
    const/4 v3, 0x0

    .line 90
    invoke-direct {v1, p0, p1, v3, v2}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 91
    .line 92
    .line 93
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :catchall_2
    move-exception p0

    .line 98
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 99
    throw p0

    .line 100
    :pswitch_3
    check-cast p1, Laq/t;

    .line 101
    .line 102
    iget-boolean p1, p1, Laq/t;->d:Z

    .line 103
    .line 104
    if-eqz p1, :cond_2

    .line 105
    .line 106
    iget-object p1, p0, Laq/q;->f:Ljava/lang/Object;

    .line 107
    .line 108
    monitor-enter p1

    .line 109
    :try_start_6
    monitor-exit p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 110
    iget-object p1, p0, Laq/q;->e:Ljava/util/concurrent/Executor;

    .line 111
    .line 112
    new-instance v0, Laq/p;

    .line 113
    .line 114
    const/4 v1, 0x0

    .line 115
    invoke-direct {v0, p0, v1}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 116
    .line 117
    .line 118
    invoke-interface {p1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 119
    .line 120
    .line 121
    goto :goto_2

    .line 122
    :catchall_3
    move-exception p0

    .line 123
    :try_start_7
    monitor-exit p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 124
    throw p0

    .line 125
    :cond_2
    :goto_2
    return-void

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public c(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/q;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Laq/t;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Laq/t;->o(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/q;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Laq/t;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public s()V
    .locals 0

    .line 1
    iget-object p0, p0, Laq/q;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Laq/t;

    .line 4
    .line 5
    invoke-virtual {p0}, Laq/t;->p()V

    .line 6
    .line 7
    .line 8
    return-void
.end method
