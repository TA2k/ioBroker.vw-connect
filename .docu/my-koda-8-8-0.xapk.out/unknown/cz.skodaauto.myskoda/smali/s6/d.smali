.class public final Ls6/d;
.super Lkp/m7;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lis/b;


# direct methods
.method public constructor <init>(Lis/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ls6/d;->a:Lis/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ls6/d;->a:Lis/b;

    .line 2
    .line 3
    iget-object p0, p0, Lis/b;->a:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ls6/h;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ls6/h;->f(Ljava/lang/Throwable;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final c(Lcom/google/firebase/messaging/w;)V
    .locals 5

    .line 1
    iget-object p0, p0, Ls6/d;->a:Lis/b;

    .line 2
    .line 3
    iput-object p1, p0, Lis/b;->c:Ljava/lang/Object;

    .line 4
    .line 5
    new-instance p1, Lrn/i;

    .line 6
    .line 7
    iget-object v0, p0, Lis/b;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lcom/google/firebase/messaging/w;

    .line 10
    .line 11
    iget-object v1, p0, Lis/b;->a:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, Ls6/h;

    .line 14
    .line 15
    iget-object v2, v1, Ls6/h;->g:Lrb0/a;

    .line 16
    .line 17
    iget-object v1, v1, Ls6/h;->i:Ls6/c;

    .line 18
    .line 19
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 20
    .line 21
    const/16 v4, 0x22

    .line 22
    .line 23
    if-lt v3, v4, :cond_0

    .line 24
    .line 25
    invoke-static {}, Ls6/k;->a()Ljava/util/Set;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-static {}, Lkp/n7;->b()Ljava/util/Set;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    :goto_0
    invoke-direct {p1, v0, v2, v1, v3}, Lrn/i;-><init>(Lcom/google/firebase/messaging/w;Lrb0/a;Ls6/c;Ljava/util/Set;)V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Lis/b;->b:Ljava/lang/Object;

    .line 38
    .line 39
    iget-object p0, p0, Lis/b;->a:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Ls6/h;

    .line 42
    .line 43
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    new-instance p1, Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 49
    .line 50
    .line 51
    iget-object v0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 58
    .line 59
    .line 60
    const/4 v0, 0x1

    .line 61
    :try_start_0
    iput v0, p0, Ls6/h;->c:I

    .line 62
    .line 63
    iget-object v0, p0, Ls6/h;->b:Landroidx/collection/g;

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 66
    .line 67
    .line 68
    iget-object v0, p0, Ls6/h;->b:Landroidx/collection/g;

    .line 69
    .line 70
    invoke-virtual {v0}, Landroidx/collection/g;->clear()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 71
    .line 72
    .line 73
    iget-object v0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 74
    .line 75
    invoke-virtual {v0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-interface {v0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 80
    .line 81
    .line 82
    iget-object v0, p0, Ls6/h;->d:Landroid/os/Handler;

    .line 83
    .line 84
    new-instance v1, Lcom/google/android/material/datepicker/n;

    .line 85
    .line 86
    iget p0, p0, Ls6/h;->c:I

    .line 87
    .line 88
    const/4 v2, 0x0

    .line 89
    invoke-direct {v1, p1, p0, v2}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/util/List;ILjava/lang/Throwable;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :catchall_0
    move-exception p1

    .line 97
    iget-object p0, p0, Ls6/h;->a:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 98
    .line 99
    invoke-virtual {p0}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    invoke-interface {p0}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 104
    .line 105
    .line 106
    throw p1
.end method
