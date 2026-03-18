.class public final synthetic Lis/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lls/a;
.implements Lks/a;
.implements Lgt/a;


# instance fields
.field public final synthetic d:Lis/b;


# direct methods
.method public synthetic constructor <init>(Lis/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lis/a;->d:Lis/b;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public b(Lgt/b;)V
    .locals 7

    .line 1
    iget-object p0, p0, Lis/a;->d:Lis/b;

    .line 2
    .line 3
    sget-object v0, Ljs/c;->a:Ljs/c;

    .line 4
    .line 5
    const-string v1, "AnalyticsConnector now available."

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ljs/c;->b(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-interface {p1}, Lgt/b;->get()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Lwr/b;

    .line 15
    .line 16
    new-instance v1, Lhu/q;

    .line 17
    .line 18
    const/16 v2, 0xd

    .line 19
    .line 20
    invoke-direct {v1, p1, v2}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Lb81/a;

    .line 24
    .line 25
    const/16 v3, 0xb

    .line 26
    .line 27
    const/4 v4, 0x0

    .line 28
    invoke-direct {v2, v3, v4}, Lb81/a;-><init>(IZ)V

    .line 29
    .line 30
    .line 31
    const-string v3, "FirebaseCrashlytics"

    .line 32
    .line 33
    const-string v4, "clx"

    .line 34
    .line 35
    check-cast p1, Lwr/c;

    .line 36
    .line 37
    invoke-virtual {p1, v4, v2}, Lwr/c;->b(Ljava/lang/String;Lb81/a;)Lrb0/a;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    const/4 v5, 0x0

    .line 42
    if-nez v4, :cond_1

    .line 43
    .line 44
    const-string v4, "Could not register AnalyticsConnectorListener with Crashlytics origin."

    .line 45
    .line 46
    const/4 v6, 0x3

    .line 47
    invoke-static {v3, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    if-eqz v6, :cond_0

    .line 52
    .line 53
    invoke-static {v3, v4, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 54
    .line 55
    .line 56
    :cond_0
    const-string v4, "crash"

    .line 57
    .line 58
    invoke-virtual {p1, v4, v2}, Lwr/c;->b(Ljava/lang/String;Lb81/a;)Lrb0/a;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    if-eqz v4, :cond_1

    .line 63
    .line 64
    const-string p1, "A new version of the Google Analytics for Firebase SDK is now available. For improved performance and compatibility with Crashlytics, please update to the latest version."

    .line 65
    .line 66
    invoke-static {v3, p1, v5}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 67
    .line 68
    .line 69
    :cond_1
    if-eqz v4, :cond_3

    .line 70
    .line 71
    const-string p1, "Registered Firebase Analytics listener."

    .line 72
    .line 73
    invoke-virtual {v0, p1}, Ljs/c;->b(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    new-instance p1, Lh6/e;

    .line 77
    .line 78
    const/16 v0, 0xd

    .line 79
    .line 80
    invoke-direct {p1, v0}, Lh6/e;-><init>(I)V

    .line 81
    .line 82
    .line 83
    new-instance v0, Lil/g;

    .line 84
    .line 85
    sget-object v3, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 86
    .line 87
    invoke-direct {v0, v1}, Lil/g;-><init>(Lhu/q;)V

    .line 88
    .line 89
    .line 90
    monitor-enter p0

    .line 91
    :try_start_0
    iget-object v1, p0, Lis/b;->a:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v1, Ljava/util/ArrayList;

    .line 94
    .line 95
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    if-eqz v3, :cond_2

    .line 104
    .line 105
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    check-cast v3, Lms/n;

    .line 110
    .line 111
    invoke-virtual {p1, v3}, Lh6/e;->g(Lms/n;)V

    .line 112
    .line 113
    .line 114
    goto :goto_0

    .line 115
    :catchall_0
    move-exception p1

    .line 116
    goto :goto_1

    .line 117
    :cond_2
    iput-object p1, v2, Lb81/a;->f:Ljava/lang/Object;

    .line 118
    .line 119
    iput-object v0, v2, Lb81/a;->e:Ljava/lang/Object;

    .line 120
    .line 121
    iput-object p1, p0, Lis/b;->c:Ljava/lang/Object;

    .line 122
    .line 123
    iput-object v0, p0, Lis/b;->b:Ljava/lang/Object;

    .line 124
    .line 125
    monitor-exit p0

    .line 126
    return-void

    .line 127
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 128
    throw p1

    .line 129
    :cond_3
    const-string p0, "Could not register Firebase Analytics listener; a listener is already registered."

    .line 130
    .line 131
    invoke-virtual {v0, p0, v5}, Ljs/c;->f(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 132
    .line 133
    .line 134
    return-void
.end method

.method public g(Lms/n;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lis/a;->d:Lis/b;

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iget-object v0, p0, Lis/b;->c:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lls/a;

    .line 7
    .line 8
    instance-of v0, v0, Lls/b;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lis/b;->a:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception p1

    .line 21
    goto :goto_1

    .line 22
    :cond_0
    :goto_0
    iget-object v0, p0, Lis/b;->c:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Lls/a;

    .line 25
    .line 26
    invoke-interface {v0, p1}, Lls/a;->g(Lms/n;)V

    .line 27
    .line 28
    .line 29
    monitor-exit p0

    .line 30
    return-void

    .line 31
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    throw p1
.end method

.method public j(Landroid/os/Bundle;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lis/a;->d:Lis/b;

    .line 2
    .line 3
    iget-object p0, p0, Lis/b;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lks/a;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Lks/a;->j(Landroid/os/Bundle;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
