.class public final synthetic Lcom/google/firebase/messaging/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcom/google/firebase/messaging/FirebaseMessaging;


# direct methods
.method public synthetic constructor <init>(Lcom/google/firebase/messaging/FirebaseMessaging;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/firebase/messaging/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/firebase/messaging/n;->e:Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 8

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/n;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/firebase/messaging/n;->e:Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->b:Landroid/content/Context;

    .line 9
    .line 10
    invoke-static {v0}, Ljp/ke;->e(Landroid/content/Context;)V

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->c:Lin/z1;

    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->i()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    invoke-static {v0}, Ljp/le;->c(Landroid/content/Context;)Landroid/content/SharedPreferences;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    const-string v4, "proxy_retention"

    .line 24
    .line 25
    invoke-interface {v3, v4}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    if-eqz v5, :cond_0

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    invoke-interface {v3, v4, v5}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-ne v3, v2, :cond_0

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_0
    iget-object v1, v1, Lin/z1;->c:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Lio/b;

    .line 42
    .line 43
    iget-object v3, v1, Lio/b;->c:Lc1/m2;

    .line 44
    .line 45
    invoke-virtual {v3}, Lc1/m2;->q()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    const v5, 0xe5ee4e0

    .line 50
    .line 51
    .line 52
    if-lt v3, v5, :cond_1

    .line 53
    .line 54
    new-instance v3, Landroid/os/Bundle;

    .line 55
    .line 56
    invoke-direct {v3}, Landroid/os/Bundle;-><init>()V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v3, v4, v2}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 60
    .line 61
    .line 62
    iget-object v1, v1, Lio/b;->b:Landroid/content/Context;

    .line 63
    .line 64
    invoke-static {v1}, Lio/o;->d(Landroid/content/Context;)Lio/o;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    new-instance v4, Lio/n;

    .line 69
    .line 70
    monitor-enter v1

    .line 71
    :try_start_0
    iget v5, v1, Lio/o;->d:I

    .line 72
    .line 73
    add-int/lit8 v6, v5, 0x1

    .line 74
    .line 75
    iput v6, v1, Lio/o;->d:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 76
    .line 77
    monitor-exit v1

    .line 78
    const/4 v6, 0x0

    .line 79
    const/4 v7, 0x4

    .line 80
    invoke-direct {v4, v5, v7, v3, v6}, Lio/n;-><init>(IILandroid/os/Bundle;I)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v1, v4}, Lio/o;->e(Lio/n;)Laq/t;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    goto :goto_0

    .line 88
    :catchall_0
    move-exception p0

    .line 89
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 90
    throw p0

    .line 91
    :cond_1
    new-instance v1, Ljava/io/IOException;

    .line 92
    .line 93
    const-string v3, "SERVICE_NOT_AVAILABLE"

    .line 94
    .line 95
    invoke-direct {v1, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-static {v1}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    :goto_0
    new-instance v3, Lha/c;

    .line 103
    .line 104
    const/4 v4, 0x0

    .line 105
    invoke-direct {v3, v4}, Lha/c;-><init>(I)V

    .line 106
    .line 107
    .line 108
    new-instance v4, Lcom/google/firebase/messaging/u;

    .line 109
    .line 110
    invoke-direct {v4, v0, v2}, Lcom/google/firebase/messaging/u;-><init>(Landroid/content/Context;Z)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v1, v3, v4}, Laq/t;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 114
    .line 115
    .line 116
    :goto_1
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->i()Z

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    if-eqz v0, :cond_2

    .line 121
    .line 122
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->h()V

    .line 123
    .line 124
    .line 125
    :cond_2
    return-void

    .line 126
    :pswitch_0
    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->e:La8/b;

    .line 127
    .line 128
    invoke-virtual {v0}, La8/b;->k()Z

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    if-eqz v0, :cond_4

    .line 133
    .line 134
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->g()Lcom/google/firebase/messaging/x;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    invoke-virtual {p0, v0}, Lcom/google/firebase/messaging/FirebaseMessaging;->k(Lcom/google/firebase/messaging/x;)Z

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    if-eqz v0, :cond_4

    .line 143
    .line 144
    monitor-enter p0

    .line 145
    :try_start_2
    iget-boolean v0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->i:Z

    .line 146
    .line 147
    if-nez v0, :cond_3

    .line 148
    .line 149
    const-wide/16 v0, 0x0

    .line 150
    .line 151
    invoke-virtual {p0, v0, v1}, Lcom/google/firebase/messaging/FirebaseMessaging;->j(J)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 152
    .line 153
    .line 154
    goto :goto_2

    .line 155
    :catchall_1
    move-exception v0

    .line 156
    goto :goto_3

    .line 157
    :cond_3
    :goto_2
    monitor-exit p0

    .line 158
    goto :goto_4

    .line 159
    :goto_3
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 160
    throw v0

    .line 161
    :cond_4
    :goto_4
    return-void

    .line 162
    nop

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
