.class public final synthetic Lcu/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/i;
.implements Laq/b;


# instance fields
.field public final synthetic d:Lcu/b;


# direct methods
.method public synthetic constructor <init>(Lcu/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcu/a;->d:Lcu/b;

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
    .locals 5

    .line 1
    check-cast p1, Ljava/lang/Void;

    .line 2
    .line 3
    iget-object p0, p0, Lcu/a;->d:Lcu/b;

    .line 4
    .line 5
    iget-object p1, p0, Lcu/b;->d:Ldu/c;

    .line 6
    .line 7
    invoke-virtual {p1}, Ldu/c;->b()Laq/j;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iget-object v0, p0, Lcu/b;->e:Ldu/c;

    .line 12
    .line 13
    invoke-virtual {v0}, Ldu/c;->b()Laq/j;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    filled-new-array {p1, v0}, [Laq/j;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-static {v1}, Ljp/l1;->g([Laq/j;)Laq/t;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    iget-object v2, p0, Lcu/b;->c:Ljava/util/concurrent/Executor;

    .line 26
    .line 27
    new-instance v3, Lbb/i;

    .line 28
    .line 29
    const/4 v4, 0x2

    .line 30
    invoke-direct {v3, p0, p1, v0, v4}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, v2, v3}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method public w(Laq/j;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object p0, p0, Lcu/a;->d:Lcu/b;

    .line 2
    .line 3
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_3

    .line 8
    .line 9
    iget-object v0, p0, Lcu/b;->d:Ldu/c;

    .line 10
    .line 11
    monitor-enter v0

    .line 12
    const/4 v1, 0x0

    .line 13
    :try_start_0
    invoke-static {v1}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iput-object v1, v0, Ldu/c;->c:Laq/t;

    .line 18
    .line 19
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 20
    iget-object v1, v0, Ldu/c;->b:Ldu/o;

    .line 21
    .line 22
    monitor-enter v1

    .line 23
    :try_start_1
    iget-object v0, v1, Ldu/o;->a:Landroid/content/Context;

    .line 24
    .line 25
    iget-object v2, v1, Ldu/o;->b:Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {v0, v2}, Landroid/content/Context;->deleteFile(Ljava/lang/String;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 28
    .line 29
    .line 30
    monitor-exit v1

    .line 31
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    check-cast p1, Ldu/e;

    .line 36
    .line 37
    if-eqz p1, :cond_1

    .line 38
    .line 39
    iget-object v0, p1, Ldu/e;->d:Lorg/json/JSONArray;

    .line 40
    .line 41
    const-string v1, "FirebaseRemoteConfig"

    .line 42
    .line 43
    iget-object v2, p0, Lcu/b;->b:Ltr/c;

    .line 44
    .line 45
    if-nez v2, :cond_0

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_0
    :try_start_2
    invoke-static {v0}, Lcu/b;->e(Lorg/json/JSONArray;)Ljava/util/ArrayList;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-virtual {v2, v0}, Ltr/c;->c(Ljava/util/ArrayList;)V
    :try_end_2
    .catch Lorg/json/JSONException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ltr/a; {:try_start_2 .. :try_end_2} :catch_0

    .line 53
    .line 54
    .line 55
    goto :goto_2

    .line 56
    :catch_0
    move-exception v0

    .line 57
    goto :goto_0

    .line 58
    :catch_1
    move-exception v0

    .line 59
    goto :goto_1

    .line 60
    :goto_0
    const-string v2, "Could not update ABT experiments."

    .line 61
    .line 62
    invoke-static {v1, v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 63
    .line 64
    .line 65
    goto :goto_2

    .line 66
    :goto_1
    const-string v2, "Could not parse ABT experiments from the JSON response."

    .line 67
    .line 68
    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 69
    .line 70
    .line 71
    :goto_2
    iget-object p0, p0, Lcu/b;->k:Lcom/google/firebase/messaging/w;

    .line 72
    .line 73
    :try_start_3
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v0, Lb81/b;

    .line 76
    .line 77
    invoke-virtual {v0, p1}, Lb81/b;->n(Ldu/e;)Lgu/d;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v0, Ljava/util/Set;

    .line 84
    .line 85
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-eqz v1, :cond_2

    .line 94
    .line 95
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    check-cast v1, Ljs/b;

    .line 100
    .line 101
    iget-object v2, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v2, Ljava/util/concurrent/Executor;

    .line 104
    .line 105
    new-instance v3, Leu/a;

    .line 106
    .line 107
    const/4 v4, 0x0

    .line 108
    invoke-direct {v3, v1, p1, v4}, Leu/a;-><init>(Ljs/b;Lgu/d;I)V

    .line 109
    .line 110
    .line 111
    invoke-interface {v2, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_3
    .catch Lcu/d; {:try_start_3 .. :try_end_3} :catch_2

    .line 112
    .line 113
    .line 114
    goto :goto_3

    .line 115
    :catch_2
    move-exception p0

    .line 116
    const-string p1, "FirebaseRemoteConfig"

    .line 117
    .line 118
    const-string v0, "Exception publishing RolloutsState to subscribers. Continuing to listen for changes."

    .line 119
    .line 120
    invoke-static {p1, v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 121
    .line 122
    .line 123
    goto :goto_4

    .line 124
    :cond_1
    const-string p0, "FirebaseRemoteConfig"

    .line 125
    .line 126
    const-string p1, "Activated configs written to disk are null."

    .line 127
    .line 128
    invoke-static {p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 129
    .line 130
    .line 131
    :cond_2
    :goto_4
    const/4 p0, 0x1

    .line 132
    goto :goto_5

    .line 133
    :catchall_0
    move-exception p0

    .line 134
    :try_start_4
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 135
    throw p0

    .line 136
    :catchall_1
    move-exception p0

    .line 137
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 138
    throw p0

    .line 139
    :cond_3
    const/4 p0, 0x0

    .line 140
    :goto_5
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    return-object p0
.end method
