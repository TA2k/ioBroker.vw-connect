.class public final Lno/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Handler$Callback;


# instance fields
.field public final synthetic d:Lno/n0;


# direct methods
.method public synthetic constructor <init>(Lno/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lno/m0;->d:Lno/n0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final handleMessage(Landroid/os/Message;)Z
    .locals 6

    .line 1
    const-string v0, "Timeout waiting for ServiceConnection callback "

    .line 2
    .line 3
    iget v1, p1, Landroid/os/Message;->what:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    if-eqz v1, :cond_4

    .line 8
    .line 9
    if-eq v1, v3, :cond_0

    .line 10
    .line 11
    return v2

    .line 12
    :cond_0
    iget-object v1, p0, Lno/m0;->d:Lno/n0;

    .line 13
    .line 14
    iget-object v1, v1, Lno/n0;->a:Ljava/util/HashMap;

    .line 15
    .line 16
    monitor-enter v1

    .line 17
    :try_start_0
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Lno/k0;

    .line 20
    .line 21
    iget-object p0, p0, Lno/m0;->d:Lno/n0;

    .line 22
    .line 23
    iget-object p0, p0, Lno/n0;->a:Ljava/util/HashMap;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Lno/l0;

    .line 30
    .line 31
    if-eqz p0, :cond_3

    .line 32
    .line 33
    iget v2, p0, Lno/l0;->b:I

    .line 34
    .line 35
    const/4 v4, 0x3

    .line 36
    if-ne v2, v4, :cond_3

    .line 37
    .line 38
    const-string v2, "GmsClientSupervisor"

    .line 39
    .line 40
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-virtual {v0, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    new-instance v4, Ljava/lang/Exception;

    .line 49
    .line 50
    invoke-direct {v4}, Ljava/lang/Exception;-><init>()V

    .line 51
    .line 52
    .line 53
    invoke-static {v2, v0, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 54
    .line 55
    .line 56
    iget-object v0, p0, Lno/l0;->f:Landroid/content/ComponentName;

    .line 57
    .line 58
    if-nez v0, :cond_1

    .line 59
    .line 60
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    const/4 v0, 0x0

    .line 64
    goto :goto_0

    .line 65
    :catchall_0
    move-exception p0

    .line 66
    goto :goto_1

    .line 67
    :cond_1
    :goto_0
    if-nez v0, :cond_2

    .line 68
    .line 69
    new-instance v0, Landroid/content/ComponentName;

    .line 70
    .line 71
    iget-object p1, p1, Lno/k0;->b:Ljava/lang/String;

    .line 72
    .line 73
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    const-string v2, "unknown"

    .line 77
    .line 78
    invoke-direct {v0, p1, v2}, Landroid/content/ComponentName;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    :cond_2
    invoke-virtual {p0, v0}, Lno/l0;->onServiceDisconnected(Landroid/content/ComponentName;)V

    .line 82
    .line 83
    .line 84
    :cond_3
    monitor-exit v1

    .line 85
    return v3

    .line 86
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 87
    throw p0

    .line 88
    :cond_4
    iget-object v0, p0, Lno/m0;->d:Lno/n0;

    .line 89
    .line 90
    iget-object v0, v0, Lno/n0;->a:Ljava/util/HashMap;

    .line 91
    .line 92
    monitor-enter v0

    .line 93
    :try_start_1
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p1, Lno/k0;

    .line 96
    .line 97
    iget-object v1, p0, Lno/m0;->d:Lno/n0;

    .line 98
    .line 99
    iget-object v1, v1, Lno/n0;->a:Ljava/util/HashMap;

    .line 100
    .line 101
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    check-cast v1, Lno/l0;

    .line 106
    .line 107
    if-eqz v1, :cond_6

    .line 108
    .line 109
    iget-object v4, v1, Lno/l0;->a:Ljava/util/HashMap;

    .line 110
    .line 111
    invoke-virtual {v4}, Ljava/util/HashMap;->isEmpty()Z

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    if-eqz v4, :cond_6

    .line 116
    .line 117
    iget-boolean v4, v1, Lno/l0;->c:Z

    .line 118
    .line 119
    if-eqz v4, :cond_5

    .line 120
    .line 121
    iget-object v4, v1, Lno/l0;->e:Lno/k0;

    .line 122
    .line 123
    iget-object v5, v1, Lno/l0;->g:Lno/n0;

    .line 124
    .line 125
    iget-object v5, v5, Lno/n0;->c:Lbp/c;

    .line 126
    .line 127
    invoke-virtual {v5, v3, v4}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    iget-object v4, v1, Lno/l0;->g:Lno/n0;

    .line 131
    .line 132
    iget-object v5, v4, Lno/n0;->d:Lso/a;

    .line 133
    .line 134
    iget-object v4, v4, Lno/n0;->b:Landroid/content/Context;

    .line 135
    .line 136
    invoke-virtual {v5, v4, v1}, Lso/a;->c(Landroid/content/Context;Landroid/content/ServiceConnection;)V

    .line 137
    .line 138
    .line 139
    iput-boolean v2, v1, Lno/l0;->c:Z

    .line 140
    .line 141
    const/4 v2, 0x2

    .line 142
    iput v2, v1, Lno/l0;->b:I

    .line 143
    .line 144
    :cond_5
    iget-object p0, p0, Lno/m0;->d:Lno/n0;

    .line 145
    .line 146
    iget-object p0, p0, Lno/n0;->a:Ljava/util/HashMap;

    .line 147
    .line 148
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    goto :goto_2

    .line 152
    :catchall_1
    move-exception p0

    .line 153
    goto :goto_3

    .line 154
    :cond_6
    :goto_2
    monitor-exit v0

    .line 155
    return v3

    .line 156
    :goto_3
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 157
    throw p0
.end method
