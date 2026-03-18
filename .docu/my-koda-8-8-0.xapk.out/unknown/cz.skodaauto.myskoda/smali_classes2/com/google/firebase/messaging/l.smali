.class public final synthetic Lcom/google/firebase/messaging/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgt/b;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/firebase/messaging/l;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lcom/google/firebase/messaging/l;->a:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {}, Lcom/google/firebase/perf/session/gauges/GaugeManager;->b()Lxt/f;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    invoke-static {}, Lcom/google/firebase/perf/session/gauges/GaugeManager;->c()Lxt/b;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_1
    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadScheduledExecutor()Ljava/util/concurrent/ScheduledExecutorService;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_2
    sget-object p0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->a:Lgs/o;

    .line 24
    .line 25
    new-instance p0, Lhs/a;

    .line 26
    .line 27
    const-string v2, "Firebase Scheduler"

    .line 28
    .line 29
    invoke-direct {p0, v2, v0, v1}, Lhs/a;-><init>(Ljava/lang/String;ILandroid/os/StrictMode$ThreadPolicy;)V

    .line 30
    .line 31
    .line 32
    invoke-static {p0}, Ljava/util/concurrent/Executors;->newSingleThreadScheduledExecutor(Ljava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ScheduledExecutorService;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_3
    sget-object p0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->a:Lgs/o;

    .line 38
    .line 39
    new-instance p0, Lhs/a;

    .line 40
    .line 41
    const-string v0, "Firebase Blocking"

    .line 42
    .line 43
    const/16 v2, 0xb

    .line 44
    .line 45
    invoke-direct {p0, v0, v2, v1}, Lhs/a;-><init>(Ljava/lang/String;ILandroid/os/StrictMode$ThreadPolicy;)V

    .line 46
    .line 47
    .line 48
    invoke-static {p0}, Ljava/util/concurrent/Executors;->newCachedThreadPool(Ljava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ExecutorService;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    new-instance v0, Lhs/f;

    .line 53
    .line 54
    sget-object v1, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->d:Lgs/o;

    .line 55
    .line 56
    invoke-virtual {v1}, Lgs/o;->get()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    check-cast v1, Ljava/util/concurrent/ScheduledExecutorService;

    .line 61
    .line 62
    invoke-direct {v0, p0, v1}, Lhs/f;-><init>(Ljava/util/concurrent/ExecutorService;Ljava/util/concurrent/ScheduledExecutorService;)V

    .line 63
    .line 64
    .line 65
    return-object v0

    .line 66
    :pswitch_4
    sget-object p0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->a:Lgs/o;

    .line 67
    .line 68
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-virtual {p0}, Ljava/lang/Runtime;->availableProcessors()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    const/4 v1, 0x2

    .line 77
    invoke-static {v1, p0}, Ljava/lang/Math;->max(II)I

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    new-instance v1, Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 82
    .line 83
    invoke-direct {v1}, Landroid/os/StrictMode$ThreadPolicy$Builder;-><init>()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1}, Landroid/os/StrictMode$ThreadPolicy$Builder;->detectAll()Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-virtual {v1}, Landroid/os/StrictMode$ThreadPolicy$Builder;->penaltyLog()Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v1}, Landroid/os/StrictMode$ThreadPolicy$Builder;->build()Landroid/os/StrictMode$ThreadPolicy;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    new-instance v2, Lhs/a;

    .line 99
    .line 100
    const-string v3, "Firebase Lite"

    .line 101
    .line 102
    invoke-direct {v2, v3, v0, v1}, Lhs/a;-><init>(Ljava/lang/String;ILandroid/os/StrictMode$ThreadPolicy;)V

    .line 103
    .line 104
    .line 105
    invoke-static {p0, v2}, Ljava/util/concurrent/Executors;->newFixedThreadPool(ILjava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ExecutorService;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    new-instance v0, Lhs/f;

    .line 110
    .line 111
    sget-object v1, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->d:Lgs/o;

    .line 112
    .line 113
    invoke-virtual {v1}, Lgs/o;->get()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v1, Ljava/util/concurrent/ScheduledExecutorService;

    .line 118
    .line 119
    invoke-direct {v0, p0, v1}, Lhs/f;-><init>(Ljava/util/concurrent/ExecutorService;Ljava/util/concurrent/ScheduledExecutorService;)V

    .line 120
    .line 121
    .line 122
    return-object v0

    .line 123
    :pswitch_5
    sget-object p0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->a:Lgs/o;

    .line 124
    .line 125
    new-instance p0, Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 126
    .line 127
    invoke-direct {p0}, Landroid/os/StrictMode$ThreadPolicy$Builder;-><init>()V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p0}, Landroid/os/StrictMode$ThreadPolicy$Builder;->detectNetwork()Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    invoke-virtual {p0}, Landroid/os/StrictMode$ThreadPolicy$Builder;->detectResourceMismatches()Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 135
    .line 136
    .line 137
    invoke-virtual {p0}, Landroid/os/StrictMode$ThreadPolicy$Builder;->detectUnbufferedIo()Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0}, Landroid/os/StrictMode$ThreadPolicy$Builder;->penaltyLog()Landroid/os/StrictMode$ThreadPolicy$Builder;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    invoke-virtual {p0}, Landroid/os/StrictMode$ThreadPolicy$Builder;->build()Landroid/os/StrictMode$ThreadPolicy;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    new-instance v0, Lhs/a;

    .line 149
    .line 150
    const-string v1, "Firebase Background"

    .line 151
    .line 152
    const/16 v2, 0xa

    .line 153
    .line 154
    invoke-direct {v0, v1, v2, p0}, Lhs/a;-><init>(Ljava/lang/String;ILandroid/os/StrictMode$ThreadPolicy;)V

    .line 155
    .line 156
    .line 157
    const/4 p0, 0x4

    .line 158
    invoke-static {p0, v0}, Ljava/util/concurrent/Executors;->newFixedThreadPool(ILjava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ExecutorService;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    new-instance v0, Lhs/f;

    .line 163
    .line 164
    sget-object v1, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->d:Lgs/o;

    .line 165
    .line 166
    invoke-virtual {v1}, Lgs/o;->get()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    check-cast v1, Ljava/util/concurrent/ScheduledExecutorService;

    .line 171
    .line 172
    invoke-direct {v0, p0, v1}, Lhs/f;-><init>(Ljava/util/concurrent/ExecutorService;Ljava/util/concurrent/ScheduledExecutorService;)V

    .line 173
    .line 174
    .line 175
    return-object v0

    .line 176
    :pswitch_6
    return-object v1

    .line 177
    :pswitch_7
    sget-object p0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 178
    .line 179
    return-object p0

    .line 180
    :pswitch_8
    sget-object p0, Lcu/j;->j:Ljava/util/Random;

    .line 181
    .line 182
    return-object v1

    .line 183
    :pswitch_9
    sget-object p0, Lcom/google/firebase/messaging/FirebaseMessaging;->k:La0/j;

    .line 184
    .line 185
    return-object v1

    .line 186
    nop

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
