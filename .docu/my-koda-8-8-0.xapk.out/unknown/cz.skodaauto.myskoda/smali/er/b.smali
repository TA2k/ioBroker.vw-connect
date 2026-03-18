.class public final Ler/b;
.super Ler/q;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ler/b;->e:I

    .line 2
    .line 3
    iput-object p1, p0, Ler/b;->f:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ler/q;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()V
    .locals 5

    .line 1
    iget v0, p0, Ler/b;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ler/b;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ler/d;

    .line 9
    .line 10
    iget-object v0, v0, Ler/d;->f:Ljava/lang/Object;

    .line 11
    .line 12
    monitor-enter v0

    .line 13
    :try_start_0
    iget-object v1, p0, Ler/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Ler/d;

    .line 16
    .line 17
    iget-object v1, v1, Ler/d;->l:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    const/4 v2, 0x0

    .line 24
    if-lez v1, :cond_0

    .line 25
    .line 26
    iget-object v1, p0, Ler/b;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v1, Ler/d;

    .line 29
    .line 30
    iget-object v1, v1, Ler/d;->l:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-lez v1, :cond_0

    .line 37
    .line 38
    iget-object p0, p0, Ler/b;->f:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Ler/d;

    .line 41
    .line 42
    iget-object p0, p0, Ler/d;->b:Ler/p;

    .line 43
    .line 44
    const-string v1, "Leaving the connection open for other ongoing calls."

    .line 45
    .line 46
    new-array v2, v2, [Ljava/lang/Object;

    .line 47
    .line 48
    invoke-virtual {p0, v1, v2}, Ler/p;->a(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    monitor-exit v0

    .line 52
    goto :goto_0

    .line 53
    :catchall_0
    move-exception p0

    .line 54
    goto :goto_1

    .line 55
    :cond_0
    iget-object v1, p0, Ler/b;->f:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v1, Ler/d;

    .line 58
    .line 59
    iget-object v3, v1, Ler/d;->n:Ler/o;

    .line 60
    .line 61
    if-eqz v3, :cond_1

    .line 62
    .line 63
    iget-object v1, v1, Ler/d;->b:Ler/p;

    .line 64
    .line 65
    const-string v3, "Unbind from service."

    .line 66
    .line 67
    new-array v4, v2, [Ljava/lang/Object;

    .line 68
    .line 69
    invoke-virtual {v1, v3, v4}, Ler/p;->a(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iget-object v1, p0, Ler/b;->f:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v1, Ler/d;

    .line 75
    .line 76
    iget-object v3, v1, Ler/d;->a:Landroid/content/Context;

    .line 77
    .line 78
    iget-object v1, v1, Ler/d;->m:Ler/c;

    .line 79
    .line 80
    invoke-virtual {v3, v1}, Landroid/content/Context;->unbindService(Landroid/content/ServiceConnection;)V

    .line 81
    .line 82
    .line 83
    iget-object v1, p0, Ler/b;->f:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v1, Ler/d;

    .line 86
    .line 87
    iput-boolean v2, v1, Ler/d;->g:Z

    .line 88
    .line 89
    const/4 v2, 0x0

    .line 90
    iput-object v2, v1, Ler/d;->n:Ler/o;

    .line 91
    .line 92
    iput-object v2, v1, Ler/d;->m:Ler/c;

    .line 93
    .line 94
    :cond_1
    iget-object p0, p0, Ler/b;->f:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast p0, Ler/d;

    .line 97
    .line 98
    invoke-virtual {p0}, Ler/d;->c()V

    .line 99
    .line 100
    .line 101
    monitor-exit v0

    .line 102
    :goto_0
    return-void

    .line 103
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 104
    throw p0

    .line 105
    :pswitch_0
    iget-object p0, p0, Ler/b;->f:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast p0, Ler/c;

    .line 108
    .line 109
    iget-object p0, p0, Ler/c;->a:Ler/d;

    .line 110
    .line 111
    iget-object v0, p0, Ler/d;->b:Ler/p;

    .line 112
    .line 113
    const-string v1, "unlinkToDeath"

    .line 114
    .line 115
    const/4 v2, 0x0

    .line 116
    new-array v3, v2, [Ljava/lang/Object;

    .line 117
    .line 118
    invoke-virtual {v0, v1, v3}, Ler/p;->a(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    iget-object v0, p0, Ler/d;->n:Ler/o;

    .line 122
    .line 123
    check-cast v0, Ler/m;

    .line 124
    .line 125
    iget-object v0, v0, Ler/m;->c:Landroid/os/IBinder;

    .line 126
    .line 127
    iget-object v1, p0, Ler/d;->k:Ler/r;

    .line 128
    .line 129
    invoke-interface {v0, v1, v2}, Landroid/os/IBinder;->unlinkToDeath(Landroid/os/IBinder$DeathRecipient;I)Z

    .line 130
    .line 131
    .line 132
    const/4 v0, 0x0

    .line 133
    iput-object v0, p0, Ler/d;->n:Ler/o;

    .line 134
    .line 135
    iput-boolean v2, p0, Ler/d;->g:Z

    .line 136
    .line 137
    return-void

    .line 138
    nop

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
