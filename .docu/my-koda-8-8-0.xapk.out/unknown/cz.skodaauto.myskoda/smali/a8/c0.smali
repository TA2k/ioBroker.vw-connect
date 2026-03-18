.class public final synthetic La8/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;ZLa8/i0;Lb8/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, La8/c0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/c0;->f:Ljava/lang/Object;

    iput-boolean p2, p0, La8/c0;->e:Z

    iput-object p3, p0, La8/c0;->g:Ljava/lang/Object;

    iput-object p4, p0, La8/c0;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lss/b;Lps/j2;Los/c;Z)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, La8/c0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/c0;->f:Ljava/lang/Object;

    iput-object p2, p0, La8/c0;->g:Ljava/lang/Object;

    iput-object p3, p0, La8/c0;->h:Ljava/lang/Object;

    iput-boolean p4, p0, La8/c0;->e:Z

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 6

    .line 1
    iget v0, p0, La8/c0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La8/c0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lss/b;

    .line 9
    .line 10
    iget-object v1, p0, La8/c0;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lps/j2;

    .line 13
    .line 14
    iget-object v2, p0, La8/c0;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Los/c;

    .line 17
    .line 18
    iget-boolean p0, p0, La8/c0;->e:Z

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    const-string v3, "disk worker: log non-fatal event to persistence"

    .line 24
    .line 25
    const-string v4, "FirebaseCrashlytics"

    .line 26
    .line 27
    const/4 v5, 0x3

    .line 28
    invoke-static {v4, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_0

    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    invoke-static {v4, v3, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 36
    .line 37
    .line 38
    :cond_0
    iget-object v0, v0, Lss/b;->f:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, Lss/a;

    .line 41
    .line 42
    iget-object v2, v2, Los/c;->a:Ljava/lang/String;

    .line 43
    .line 44
    invoke-virtual {v0, v1, v2, p0}, Lss/a;->d(Lps/j2;Ljava/lang/String;Z)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :pswitch_0
    iget-object v0, p0, La8/c0;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v0, Landroid/content/Context;

    .line 51
    .line 52
    iget-boolean v1, p0, La8/c0;->e:Z

    .line 53
    .line 54
    iget-object v2, p0, La8/c0;->g:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v2, La8/i0;

    .line 57
    .line 58
    iget-object p0, p0, La8/c0;->h:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast p0, Lb8/k;

    .line 61
    .line 62
    const-string v3, "media_metrics"

    .line 63
    .line 64
    invoke-virtual {v0, v3}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    invoke-static {v3}, La6/c;->a(Ljava/lang/Object;)Landroid/media/metrics/MediaMetricsManager;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    if-nez v3, :cond_1

    .line 73
    .line 74
    const/4 v0, 0x0

    .line 75
    goto :goto_0

    .line 76
    :cond_1
    new-instance v4, Lb8/j;

    .line 77
    .line 78
    invoke-static {v3}, La6/c;->k(Landroid/media/metrics/MediaMetricsManager;)Landroid/media/metrics/PlaybackSession;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    invoke-direct {v4, v0, v3}, Lb8/j;-><init>(Landroid/content/Context;Landroid/media/metrics/PlaybackSession;)V

    .line 83
    .line 84
    .line 85
    move-object v0, v4

    .line 86
    :goto_0
    if-nez v0, :cond_2

    .line 87
    .line 88
    const-string p0, "ExoPlayerImpl"

    .line 89
    .line 90
    const-string v0, "MediaMetricsService unavailable."

    .line 91
    .line 92
    invoke-static {p0, v0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_2
    if-eqz v1, :cond_3

    .line 97
    .line 98
    iget-object v1, v2, La8/i0;->w:Lb8/e;

    .line 99
    .line 100
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    iget-object v1, v1, Lb8/e;->i:Le30/v;

    .line 104
    .line 105
    invoke-virtual {v1, v0}, Le30/v;->a(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    :cond_3
    iget-object v0, v0, Lb8/j;->d:Landroid/media/metrics/PlaybackSession;

    .line 109
    .line 110
    invoke-static {v0}, Lb8/h;->b(Landroid/media/metrics/PlaybackSession;)Landroid/media/metrics/LogSessionId;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    monitor-enter p0

    .line 115
    :try_start_0
    iget-object v1, p0, Lb8/k;->b:Laq/a;

    .line 116
    .line 117
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    iget-object v2, v1, Laq/a;->e:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v2, Landroid/media/metrics/LogSessionId;

    .line 123
    .line 124
    invoke-static {}, Lb8/h;->a()Landroid/media/metrics/LogSessionId;

    .line 125
    .line 126
    .line 127
    invoke-static {v2}, Lb8/h;->y(Landroid/media/metrics/LogSessionId;)Z

    .line 128
    .line 129
    .line 130
    move-result v2

    .line 131
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 132
    .line 133
    .line 134
    iput-object v0, v1, Laq/a;->e:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 135
    .line 136
    monitor-exit p0

    .line 137
    :goto_1
    return-void

    .line 138
    :catchall_0
    move-exception v0

    .line 139
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 140
    throw v0

    .line 141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
