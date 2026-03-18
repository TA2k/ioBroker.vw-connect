.class public final synthetic Lfv/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Executor;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lj0/a;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lfv/o;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Lfv/o;->e:Ljava/lang/Object;

    .line 4
    new-instance v0, Ljava/util/ArrayDeque;

    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    iput-object v0, p0, Lfv/o;->f:Ljava/lang/Object;

    .line 5
    iput-object p1, p0, Lfv/o;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/concurrent/Executor;La0/j;Laq/a;Laq/k;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lfv/o;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lfv/o;->e:Ljava/lang/Object;

    iput-object p2, p0, Lfv/o;->f:Ljava/lang/Object;

    iput-object p3, p0, Lfv/o;->g:Ljava/lang/Object;

    iput-object p4, p0, Lfv/o;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lfv/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lfv/o;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Ljava/util/ArrayDeque;

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Ljava/lang/Runnable;

    .line 13
    .line 14
    iput-object v1, p0, Lfv/o;->h:Ljava/lang/Object;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Lfv/o;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lj0/a;

    .line 21
    .line 22
    invoke-virtual {p0, v1}, Lj0/a;->execute(Ljava/lang/Runnable;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    :goto_0
    monitor-exit v0

    .line 29
    return-void

    .line 30
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    throw p0
.end method

.method public final execute(Ljava/lang/Runnable;)V
    .locals 4

    .line 1
    iget v0, p0, Lfv/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lfv/o;->e:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    iget-object v1, p0, Lfv/o;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Ljava/util/ArrayDeque;

    .line 12
    .line 13
    new-instance v2, La8/z;

    .line 14
    .line 15
    const/16 v3, 0x1b

    .line 16
    .line 17
    invoke-direct {v2, v3, p0, p1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, v2}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, Lfv/o;->h:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p1, Ljava/lang/Runnable;

    .line 26
    .line 27
    if-nez p1, :cond_0

    .line 28
    .line 29
    invoke-virtual {p0}, Lfv/o;->a()V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    :goto_0
    monitor-exit v0

    .line 36
    return-void

    .line 37
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0

    .line 39
    :pswitch_0
    iget-object v0, p0, Lfv/o;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 42
    .line 43
    :try_start_1
    invoke-interface {v0, p1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :catch_0
    move-exception p1

    .line 48
    iget-object v0, p0, Lfv/o;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v0, La0/j;

    .line 51
    .line 52
    iget-object v0, v0, La0/j;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Laq/t;

    .line 55
    .line 56
    invoke-virtual {v0}, Laq/t;->h()Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-eqz v0, :cond_1

    .line 61
    .line 62
    iget-object p0, p0, Lfv/o;->g:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p0, Laq/a;

    .line 65
    .line 66
    invoke-virtual {p0}, Laq/a;->k()V

    .line 67
    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_1
    iget-object p0, p0, Lfv/o;->h:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Laq/k;

    .line 73
    .line 74
    invoke-virtual {p0, p1}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 75
    .line 76
    .line 77
    :goto_2
    throw p1

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
