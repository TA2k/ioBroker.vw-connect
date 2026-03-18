.class public final Lno/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lko/n;


# instance fields
.field public final synthetic a:Lcq/b2;

.field public final synthetic b:Laq/k;

.field public final synthetic c:Lno/m;


# direct methods
.method public constructor <init>(Lcq/b2;Laq/k;Lno/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lno/t;->a:Lcq/b2;

    .line 5
    .line 6
    iput-object p2, p0, Lno/t;->b:Laq/k;

    .line 7
    .line 8
    iput-object p3, p0, Lno/t;->c:Lno/m;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/android/gms/common/api/Status;)V
    .locals 5

    .line 1
    invoke-virtual {p1}, Lcom/google/android/gms/common/api/Status;->x0()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    iget-object p1, p0, Lno/t;->a:Lcq/b2;

    .line 8
    .line 9
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 10
    .line 11
    iget-boolean v1, p1, Lcom/google/android/gms/common/api/internal/BasePendingResult;->j:Z

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    xor-int/2addr v1, v2

    .line 15
    const-string v3, "Result has already been consumed."

    .line 16
    .line 17
    invoke-static {v3, v1}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 18
    .line 19
    .line 20
    :try_start_0
    iget-object v1, p1, Lcom/google/android/gms/common/api/internal/BasePendingResult;->e:Ljava/util/concurrent/CountDownLatch;

    .line 21
    .line 22
    const-wide/16 v3, 0x0

    .line 23
    .line 24
    invoke-virtual {v1, v3, v4, v0}, Ljava/util/concurrent/CountDownLatch;->await(JLjava/util/concurrent/TimeUnit;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    sget-object v0, Lcom/google/android/gms/common/api/Status;->j:Lcom/google/android/gms/common/api/Status;

    .line 31
    .line 32
    invoke-virtual {p1, v0}, Lcom/google/android/gms/common/api/internal/BasePendingResult;->d(Lcom/google/android/gms/common/api/Status;)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :catch_0
    sget-object v0, Lcom/google/android/gms/common/api/Status;->i:Lcom/google/android/gms/common/api/Status;

    .line 37
    .line 38
    invoke-virtual {p1, v0}, Lcom/google/android/gms/common/api/internal/BasePendingResult;->d(Lcom/google/android/gms/common/api/Status;)V

    .line 39
    .line 40
    .line 41
    :cond_0
    :goto_0
    invoke-virtual {p1}, Lcom/google/android/gms/common/api/internal/BasePendingResult;->e()Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    const-string v1, "Result is not ready."

    .line 46
    .line 47
    invoke-static {v1, v0}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 48
    .line 49
    .line 50
    iget-object v0, p1, Lcom/google/android/gms/common/api/internal/BasePendingResult;->d:Ljava/lang/Object;

    .line 51
    .line 52
    monitor-enter v0

    .line 53
    :try_start_1
    iget-boolean v1, p1, Lcom/google/android/gms/common/api/internal/BasePendingResult;->j:Z

    .line 54
    .line 55
    xor-int/2addr v1, v2

    .line 56
    const-string v3, "Result has already been consumed."

    .line 57
    .line 58
    invoke-static {v3, v1}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1}, Lcom/google/android/gms/common/api/internal/BasePendingResult;->e()Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    const-string v3, "Result is not ready."

    .line 66
    .line 67
    invoke-static {v3, v1}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 68
    .line 69
    .line 70
    iget-object v1, p1, Lcom/google/android/gms/common/api/internal/BasePendingResult;->h:Lko/p;

    .line 71
    .line 72
    const/4 v3, 0x0

    .line 73
    iput-object v3, p1, Lcom/google/android/gms/common/api/internal/BasePendingResult;->h:Lko/p;

    .line 74
    .line 75
    iput-boolean v2, p1, Lcom/google/android/gms/common/api/internal/BasePendingResult;->j:Z

    .line 76
    .line 77
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 78
    iget-object p1, p1, Lcom/google/android/gms/common/api/internal/BasePendingResult;->g:Ljava/util/concurrent/atomic/AtomicReference;

    .line 79
    .line 80
    invoke-virtual {p1, v3}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    if-nez p1, :cond_1

    .line 85
    .line 86
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    iget-object p1, p0, Lno/t;->b:Laq/k;

    .line 90
    .line 91
    iget-object p0, p0, Lno/t;->c:Lno/m;

    .line 92
    .line 93
    invoke-interface {p0, v1}, Lno/m;->k(Lko/p;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-virtual {p1, p0}, Laq/k;->b(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 102
    .line 103
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :catchall_0
    move-exception p0

    .line 108
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 109
    throw p0

    .line 110
    :cond_2
    iget-object p0, p0, Lno/t;->b:Laq/k;

    .line 111
    .line 112
    invoke-static {p1}, Lno/c0;->m(Lcom/google/android/gms/common/api/Status;)Lko/e;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    invoke-virtual {p0, p1}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 117
    .line 118
    .line 119
    return-void
.end method
