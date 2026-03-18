.class public final Lyt/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpt/b;


# static fields
.field public static final u:Lst/a;

.field public static final v:Lyt/h;


# instance fields
.field public final d:Ljava/util/concurrent/ConcurrentHashMap;

.field public final e:Ljava/util/concurrent/ConcurrentLinkedQueue;

.field public final f:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public g:Lsr/f;

.field public h:Lot/b;

.field public i:Lht/d;

.field public j:Lgt/b;

.field public k:Lyt/a;

.field public final l:Ljava/util/concurrent/ThreadPoolExecutor;

.field public m:Landroid/content/Context;

.field public n:Lqt/a;

.field public o:Lyt/d;

.field public p:Lpt/c;

.field public q:Lau/e;

.field public r:Ljava/lang/String;

.field public s:Ljava/lang/String;

.field public t:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lyt/h;->u:Lst/a;

    .line 6
    .line 7
    new-instance v0, Lyt/h;

    .line 8
    .line 9
    invoke-direct {v0}, Lyt/h;-><init>()V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lyt/h;->v:Lyt/h;

    .line 13
    .line 14
    return-void
.end method

.method public constructor <init>()V
    .locals 9

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lyt/h;->e:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 10
    .line 11
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lyt/h;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 18
    .line 19
    iput-boolean v1, p0, Lyt/h;->t:Z

    .line 20
    .line 21
    new-instance v2, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 22
    .line 23
    sget-object v7, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 24
    .line 25
    new-instance v8, Ljava/util/concurrent/LinkedBlockingQueue;

    .line 26
    .line 27
    invoke-direct {v8}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 28
    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    const/4 v4, 0x1

    .line 32
    const-wide/16 v5, 0xa

    .line 33
    .line 34
    invoke-direct/range {v2 .. v8}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;)V

    .line 35
    .line 36
    .line 37
    iput-object v2, p0, Lyt/h;->l:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 38
    .line 39
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 40
    .line 41
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 42
    .line 43
    .line 44
    iput-object v0, p0, Lyt/h;->d:Ljava/util/concurrent/ConcurrentHashMap;

    .line 45
    .line 46
    const/16 p0, 0x32

    .line 47
    .line 48
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    const-string v1, "KEY_AVAILABLE_TRACES_FOR_CACHING"

    .line 53
    .line 54
    invoke-virtual {v0, v1, p0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    const-string v1, "KEY_AVAILABLE_NETWORK_REQUESTS_FOR_CACHING"

    .line 58
    .line 59
    invoke-virtual {v0, v1, p0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    const-string v1, "KEY_AVAILABLE_GAUGES_FOR_CACHING"

    .line 63
    .line 64
    invoke-virtual {v0, v1, p0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public static a(Lau/u;)Ljava/lang/String;
    .locals 8

    .line 1
    invoke-interface {p0}, Lau/u;->d()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const-string v1, "ms)"

    .line 6
    .line 7
    const-wide v2, 0x408f400000000000L    # 1000.0

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    const-string v4, "#.####"

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-interface {p0}, Lau/u;->e()Lau/a0;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0}, Lau/a0;->G()J

    .line 21
    .line 22
    .line 23
    move-result-wide v5

    .line 24
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 25
    .line 26
    invoke-virtual {p0}, Lau/a0;->H()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    new-instance v0, Ljava/text/DecimalFormat;

    .line 31
    .line 32
    invoke-direct {v0, v4}, Ljava/text/DecimalFormat;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    long-to-double v4, v5

    .line 36
    div-double/2addr v4, v2

    .line 37
    invoke-virtual {v0, v4, v5}, Ljava/text/NumberFormat;->format(D)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    const-string v2, "trace metric: "

    .line 42
    .line 43
    const-string v3, " (duration: "

    .line 44
    .line 45
    invoke-static {v2, p0, v3, v0, v1}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0

    .line 50
    :cond_0
    invoke-interface {p0}, Lau/u;->b()Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_3

    .line 55
    .line 56
    invoke-interface {p0}, Lau/u;->c()Lau/r;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {p0}, Lau/r;->W()Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-eqz v0, :cond_1

    .line 65
    .line 66
    invoke-virtual {p0}, Lau/r;->N()J

    .line 67
    .line 68
    .line 69
    move-result-wide v5

    .line 70
    goto :goto_0

    .line 71
    :cond_1
    const-wide/16 v5, 0x0

    .line 72
    .line 73
    :goto_0
    invoke-virtual {p0}, Lau/r;->S()Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    if-eqz v0, :cond_2

    .line 78
    .line 79
    invoke-virtual {p0}, Lau/r;->I()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    goto :goto_1

    .line 88
    :cond_2
    const-string v0, "UNKNOWN"

    .line 89
    .line 90
    :goto_1
    sget-object v7, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 91
    .line 92
    invoke-virtual {p0}, Lau/r;->P()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    new-instance v7, Ljava/text/DecimalFormat;

    .line 97
    .line 98
    invoke-direct {v7, v4}, Ljava/text/DecimalFormat;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    long-to-double v4, v5

    .line 102
    div-double/2addr v4, v2

    .line 103
    invoke-virtual {v7, v4, v5}, Ljava/text/NumberFormat;->format(D)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    const-string v3, " (responseCode: "

    .line 108
    .line 109
    const-string v4, ", responseTime: "

    .line 110
    .line 111
    const-string v5, "network request trace: "

    .line 112
    .line 113
    invoke-static {v5, p0, v3, v0, v4}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-static {p0, v2, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    return-object p0

    .line 122
    :cond_3
    invoke-interface {p0}, Lau/u;->a()Z

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    if-eqz v0, :cond_4

    .line 127
    .line 128
    invoke-interface {p0}, Lau/u;->f()Lau/o;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 133
    .line 134
    invoke-virtual {p0}, Lau/o;->A()Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    invoke-virtual {p0}, Lau/o;->x()I

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    invoke-virtual {p0}, Lau/o;->w()I

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    new-instance v2, Ljava/lang/StringBuilder;

    .line 147
    .line 148
    const-string v3, "gauges (hasMetadata: "

    .line 149
    .line 150
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    const-string v0, ", cpuGaugeCount: "

    .line 157
    .line 158
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    const-string v0, ", memoryGaugeCount: "

    .line 165
    .line 166
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    const-string v0, ")"

    .line 170
    .line 171
    invoke-static {p0, v0, v2}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    return-object p0

    .line 176
    :cond_4
    const-string p0, "log"

    .line 177
    .line 178
    return-object p0
.end method


# virtual methods
.method public final b(Lau/t;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Lau/t;->d()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lyt/h;->p:Lpt/c;

    .line 8
    .line 9
    const-string p1, "_fstec"

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lpt/c;->b(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    invoke-virtual {p1}, Lau/t;->b()Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-eqz p1, :cond_1

    .line 20
    .line 21
    iget-object p0, p0, Lyt/h;->p:Lpt/c;

    .line 22
    .line 23
    const-string p1, "_fsntc"

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lpt/c;->b(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    :cond_1
    return-void
.end method

.method public final c(Lau/a0;Lau/i;)V
    .locals 2

    .line 1
    new-instance v0, Lyt/f;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p0, p1, p2, v1}, Lyt/f;-><init>(Lyt/h;Lcom/google/protobuf/p;Lau/i;I)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lyt/h;->l:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final d(Lau/s;Lau/i;)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    iget-object v0, v1, Lyt/h;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v4, 0x1

    .line 14
    if-nez v0, :cond_3

    .line 15
    .line 16
    iget-object v0, v1, Lyt/h;->d:Ljava/util/concurrent/ConcurrentHashMap;

    .line 17
    .line 18
    const-string v5, "KEY_AVAILABLE_TRACES_FOR_CACHING"

    .line 19
    .line 20
    invoke-virtual {v0, v5}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v6

    .line 24
    check-cast v6, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    const-string v8, "KEY_AVAILABLE_NETWORK_REQUESTS_FOR_CACHING"

    .line 31
    .line 32
    invoke-virtual {v0, v8}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v9

    .line 36
    check-cast v9, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result v10

    .line 42
    const-string v11, "KEY_AVAILABLE_GAUGES_FOR_CACHING"

    .line 43
    .line 44
    invoke-virtual {v0, v11}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v12

    .line 48
    check-cast v12, Ljava/lang/Integer;

    .line 49
    .line 50
    invoke-virtual {v12}, Ljava/lang/Integer;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result v13

    .line 54
    invoke-virtual {v2}, Lau/s;->d()Z

    .line 55
    .line 56
    .line 57
    move-result v14

    .line 58
    if-eqz v14, :cond_0

    .line 59
    .line 60
    if-lez v7, :cond_0

    .line 61
    .line 62
    sub-int/2addr v7, v4

    .line 63
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    invoke-virtual {v0, v5, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_0
    invoke-virtual {v2}, Lau/s;->b()Z

    .line 72
    .line 73
    .line 74
    move-result v5

    .line 75
    if-eqz v5, :cond_1

    .line 76
    .line 77
    if-lez v10, :cond_1

    .line 78
    .line 79
    sub-int/2addr v10, v4

    .line 80
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    invoke-virtual {v0, v8, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_1
    invoke-virtual {v2}, Lau/s;->a()Z

    .line 89
    .line 90
    .line 91
    move-result v5

    .line 92
    if-eqz v5, :cond_2

    .line 93
    .line 94
    if-lez v13, :cond_2

    .line 95
    .line 96
    sub-int/2addr v13, v4

    .line 97
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    invoke-virtual {v0, v11, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    :goto_0
    sget-object v0, Lyt/h;->u:Lst/a;

    .line 105
    .line 106
    const-string v4, "Transport is not initialized yet, %s will be queued for to be dispatched later"

    .line 107
    .line 108
    invoke-static {v2}, Lyt/h;->a(Lau/u;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    invoke-virtual {v0, v4, v5}, Lst/a;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-object v0, v1, Lyt/h;->e:Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 120
    .line 121
    new-instance v1, Lyt/b;

    .line 122
    .line 123
    invoke-direct {v1, v2, v3}, Lyt/b;-><init>(Lau/s;Lau/i;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v0, v1}, Ljava/util/concurrent/ConcurrentLinkedQueue;->add(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    return-void

    .line 130
    :cond_2
    sget-object v0, Lyt/h;->u:Lst/a;

    .line 131
    .line 132
    const-string v1, "%s is not allowed to cache. Cache exhausted the limit (availableTracesForCaching: %d, availableNetworkRequestsForCaching: %d, availableGaugesForCaching: %d)."

    .line 133
    .line 134
    invoke-static {v2}, Lyt/h;->a(Lau/u;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    filled-new-array {v2, v6, v9, v12}, [Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    invoke-virtual {v0, v1, v2}, Lst/a;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    return-void

    .line 146
    :cond_3
    sget-object v5, Lyt/h;->u:Lst/a;

    .line 147
    .line 148
    iget-object v0, v1, Lyt/h;->n:Lqt/a;

    .line 149
    .line 150
    invoke-virtual {v0}, Lqt/a;->o()Z

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    const/4 v6, 0x0

    .line 155
    if-eqz v0, :cond_6

    .line 156
    .line 157
    iget-object v0, v1, Lyt/h;->q:Lau/e;

    .line 158
    .line 159
    iget-object v0, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 160
    .line 161
    check-cast v0, Lau/g;

    .line 162
    .line 163
    invoke-virtual {v0}, Lau/g;->A()Z

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    if-eqz v0, :cond_4

    .line 168
    .line 169
    iget-boolean v0, v1, Lyt/h;->t:Z

    .line 170
    .line 171
    if-nez v0, :cond_4

    .line 172
    .line 173
    goto :goto_6

    .line 174
    :cond_4
    :try_start_0
    iget-object v0, v1, Lyt/h;->i:Lht/d;

    .line 175
    .line 176
    check-cast v0, Lht/c;

    .line 177
    .line 178
    invoke-virtual {v0}, Lht/c;->c()Laq/t;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    sget-object v7, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 183
    .line 184
    const-wide/32 v8, 0xea60

    .line 185
    .line 186
    .line 187
    invoke-static {v0, v8, v9, v7}, Ljp/l1;->b(Laq/j;JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    check-cast v0, Ljava/lang/String;
    :try_end_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_0 .. :try_end_0} :catch_0

    .line 192
    .line 193
    goto :goto_5

    .line 194
    :catch_0
    move-exception v0

    .line 195
    goto :goto_1

    .line 196
    :catch_1
    move-exception v0

    .line 197
    goto :goto_2

    .line 198
    :catch_2
    move-exception v0

    .line 199
    goto :goto_3

    .line 200
    :goto_1
    const-string v7, "Task to retrieve Installation Id is timed out: %s"

    .line 201
    .line 202
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    invoke-virtual {v5, v7, v0}, Lst/a;->c(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    goto :goto_4

    .line 214
    :goto_2
    const-string v7, "Task to retrieve Installation Id is interrupted: %s"

    .line 215
    .line 216
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    invoke-virtual {v5, v7, v0}, Lst/a;->c(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    goto :goto_4

    .line 228
    :goto_3
    const-string v7, "Unable to retrieve Installation Id: %s"

    .line 229
    .line 230
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v0

    .line 238
    invoke-virtual {v5, v7, v0}, Lst/a;->c(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 239
    .line 240
    .line 241
    :goto_4
    move-object v0, v6

    .line 242
    :goto_5
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 243
    .line 244
    .line 245
    move-result v7

    .line 246
    if-nez v7, :cond_5

    .line 247
    .line 248
    iget-object v5, v1, Lyt/h;->q:Lau/e;

    .line 249
    .line 250
    invoke-virtual {v5}, Lcom/google/protobuf/n;->j()V

    .line 251
    .line 252
    .line 253
    iget-object v5, v5, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 254
    .line 255
    check-cast v5, Lau/g;

    .line 256
    .line 257
    invoke-static {v5, v0}, Lau/g;->v(Lau/g;Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    goto :goto_6

    .line 261
    :cond_5
    const-string v0, "Firebase Installation Id is empty, contact Firebase Support for debugging."

    .line 262
    .line 263
    invoke-virtual {v5, v0}, Lst/a;->f(Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    :cond_6
    :goto_6
    iget-object v0, v1, Lyt/h;->q:Lau/e;

    .line 267
    .line 268
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 269
    .line 270
    .line 271
    iget-object v5, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 272
    .line 273
    check-cast v5, Lau/g;

    .line 274
    .line 275
    invoke-static {v5, v3}, Lau/g;->t(Lau/g;Lau/i;)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {v2}, Lau/s;->d()Z

    .line 279
    .line 280
    .line 281
    move-result v3

    .line 282
    if-nez v3, :cond_7

    .line 283
    .line 284
    invoke-virtual {v2}, Lau/s;->b()Z

    .line 285
    .line 286
    .line 287
    move-result v3

    .line 288
    if-eqz v3, :cond_a

    .line 289
    .line 290
    :cond_7
    iget-object v3, v0, Lcom/google/protobuf/n;->d:Lcom/google/protobuf/p;

    .line 291
    .line 292
    const/4 v5, 0x5

    .line 293
    invoke-virtual {v3, v5}, Lcom/google/protobuf/p;->k(I)Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v3

    .line 297
    check-cast v3, Lcom/google/protobuf/n;

    .line 298
    .line 299
    invoke-virtual {v0}, Lcom/google/protobuf/n;->i()Lcom/google/protobuf/p;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    iput-object v0, v3, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 304
    .line 305
    move-object v0, v3

    .line 306
    check-cast v0, Lau/e;

    .line 307
    .line 308
    iget-object v3, v1, Lyt/h;->h:Lot/b;

    .line 309
    .line 310
    if-nez v3, :cond_8

    .line 311
    .line 312
    iget-object v3, v1, Lyt/h;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 313
    .line 314
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 315
    .line 316
    .line 317
    move-result v3

    .line 318
    if-eqz v3, :cond_8

    .line 319
    .line 320
    sget-object v3, Lot/b;->b:Lst/a;

    .line 321
    .line 322
    invoke-static {}, Lsr/f;->c()Lsr/f;

    .line 323
    .line 324
    .line 325
    move-result-object v3

    .line 326
    const-class v5, Lot/b;

    .line 327
    .line 328
    invoke-virtual {v3, v5}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v3

    .line 332
    check-cast v3, Lot/b;

    .line 333
    .line 334
    iput-object v3, v1, Lyt/h;->h:Lot/b;

    .line 335
    .line 336
    :cond_8
    iget-object v3, v1, Lyt/h;->h:Lot/b;

    .line 337
    .line 338
    if-eqz v3, :cond_9

    .line 339
    .line 340
    new-instance v5, Ljava/util/HashMap;

    .line 341
    .line 342
    iget-object v3, v3, Lot/b;->a:Ljava/util/concurrent/ConcurrentHashMap;

    .line 343
    .line 344
    invoke-direct {v5, v3}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 345
    .line 346
    .line 347
    goto :goto_7

    .line 348
    :cond_9
    sget-object v5, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 349
    .line 350
    :goto_7
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 351
    .line 352
    .line 353
    iget-object v3, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 354
    .line 355
    check-cast v3, Lau/g;

    .line 356
    .line 357
    invoke-static {v3}, Lau/g;->u(Lau/g;)Lcom/google/protobuf/i0;

    .line 358
    .line 359
    .line 360
    move-result-object v3

    .line 361
    invoke-virtual {v3, v5}, Lcom/google/protobuf/i0;->putAll(Ljava/util/Map;)V

    .line 362
    .line 363
    .line 364
    :cond_a
    invoke-virtual {v2}, Lcom/google/protobuf/n;->j()V

    .line 365
    .line 366
    .line 367
    iget-object v3, v2, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 368
    .line 369
    check-cast v3, Lau/t;

    .line 370
    .line 371
    invoke-virtual {v0}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 372
    .line 373
    .line 374
    move-result-object v0

    .line 375
    check-cast v0, Lau/g;

    .line 376
    .line 377
    invoke-static {v3, v0}, Lau/t;->s(Lau/t;Lau/g;)V

    .line 378
    .line 379
    .line 380
    invoke-virtual {v2}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 381
    .line 382
    .line 383
    move-result-object v0

    .line 384
    check-cast v0, Lau/t;

    .line 385
    .line 386
    iget-object v2, v1, Lyt/h;->n:Lqt/a;

    .line 387
    .line 388
    invoke-virtual {v2}, Lqt/a;->o()Z

    .line 389
    .line 390
    .line 391
    move-result v2

    .line 392
    const/4 v3, 0x0

    .line 393
    if-nez v2, :cond_b

    .line 394
    .line 395
    sget-object v2, Lyt/h;->u:Lst/a;

    .line 396
    .line 397
    const-string v4, "Performance collection is not enabled, dropping %s"

    .line 398
    .line 399
    invoke-static {v0}, Lyt/h;->a(Lau/u;)Ljava/lang/String;

    .line 400
    .line 401
    .line 402
    move-result-object v5

    .line 403
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    move-result-object v5

    .line 407
    invoke-virtual {v2, v4, v5}, Lst/a;->e(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 408
    .line 409
    .line 410
    :goto_8
    move v4, v3

    .line 411
    goto/16 :goto_1a

    .line 412
    .line 413
    :cond_b
    invoke-virtual {v0}, Lau/t;->w()Lau/g;

    .line 414
    .line 415
    .line 416
    move-result-object v2

    .line 417
    invoke-virtual {v2}, Lau/g;->A()Z

    .line 418
    .line 419
    .line 420
    move-result v2

    .line 421
    if-nez v2, :cond_c

    .line 422
    .line 423
    sget-object v2, Lyt/h;->u:Lst/a;

    .line 424
    .line 425
    const-string v4, "App Instance ID is null or empty, dropping %s"

    .line 426
    .line 427
    invoke-static {v0}, Lyt/h;->a(Lau/u;)Ljava/lang/String;

    .line 428
    .line 429
    .line 430
    move-result-object v5

    .line 431
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    move-result-object v5

    .line 435
    invoke-virtual {v2, v4, v5}, Lst/a;->g(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 436
    .line 437
    .line 438
    goto :goto_8

    .line 439
    :cond_c
    iget-object v2, v1, Lyt/h;->m:Landroid/content/Context;

    .line 440
    .line 441
    sget-object v5, Lut/e;->a:Ljava/util/regex/Pattern;

    .line 442
    .line 443
    new-instance v5, Ljava/util/ArrayList;

    .line 444
    .line 445
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 446
    .line 447
    .line 448
    invoke-virtual {v0}, Lau/t;->d()Z

    .line 449
    .line 450
    .line 451
    move-result v7

    .line 452
    if-eqz v7, :cond_d

    .line 453
    .line 454
    new-instance v7, Lut/d;

    .line 455
    .line 456
    invoke-virtual {v0}, Lau/t;->e()Lau/a0;

    .line 457
    .line 458
    .line 459
    move-result-object v8

    .line 460
    invoke-direct {v7, v8}, Lut/d;-><init>(Lau/a0;)V

    .line 461
    .line 462
    .line 463
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 464
    .line 465
    .line 466
    :cond_d
    invoke-virtual {v0}, Lau/t;->b()Z

    .line 467
    .line 468
    .line 469
    move-result v7

    .line 470
    if-eqz v7, :cond_e

    .line 471
    .line 472
    new-instance v7, Lut/c;

    .line 473
    .line 474
    invoke-virtual {v0}, Lau/t;->c()Lau/r;

    .line 475
    .line 476
    .line 477
    move-result-object v8

    .line 478
    invoke-direct {v7, v8, v2}, Lut/c;-><init>(Lau/r;Landroid/content/Context;)V

    .line 479
    .line 480
    .line 481
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 482
    .line 483
    .line 484
    :cond_e
    invoke-virtual {v0}, Lau/t;->x()Z

    .line 485
    .line 486
    .line 487
    move-result v2

    .line 488
    if-eqz v2, :cond_f

    .line 489
    .line 490
    new-instance v2, Lut/a;

    .line 491
    .line 492
    invoke-virtual {v0}, Lau/t;->w()Lau/g;

    .line 493
    .line 494
    .line 495
    move-result-object v7

    .line 496
    invoke-direct {v2, v7}, Lut/a;-><init>(Lau/g;)V

    .line 497
    .line 498
    .line 499
    invoke-virtual {v5, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 500
    .line 501
    .line 502
    :cond_f
    invoke-virtual {v0}, Lau/t;->a()Z

    .line 503
    .line 504
    .line 505
    move-result v2

    .line 506
    if-eqz v2, :cond_10

    .line 507
    .line 508
    new-instance v2, Lut/b;

    .line 509
    .line 510
    invoke-virtual {v0}, Lau/t;->f()Lau/o;

    .line 511
    .line 512
    .line 513
    move-result-object v7

    .line 514
    invoke-direct {v2, v7}, Lut/b;-><init>(Lau/o;)V

    .line 515
    .line 516
    .line 517
    invoke-virtual {v5, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 518
    .line 519
    .line 520
    :cond_10
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 521
    .line 522
    .line 523
    move-result v2

    .line 524
    if-eqz v2, :cond_11

    .line 525
    .line 526
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 527
    .line 528
    .line 529
    move-result-object v2

    .line 530
    const-string v4, "No validators found for PerfMetric."

    .line 531
    .line 532
    invoke-virtual {v2, v4}, Lst/a;->a(Ljava/lang/String;)V

    .line 533
    .line 534
    .line 535
    goto :goto_9

    .line 536
    :cond_11
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 537
    .line 538
    .line 539
    move-result-object v2

    .line 540
    :cond_12
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 541
    .line 542
    .line 543
    move-result v5

    .line 544
    if-eqz v5, :cond_13

    .line 545
    .line 546
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 547
    .line 548
    .line 549
    move-result-object v5

    .line 550
    check-cast v5, Lut/e;

    .line 551
    .line 552
    invoke-virtual {v5}, Lut/e;->a()Z

    .line 553
    .line 554
    .line 555
    move-result v5

    .line 556
    if-nez v5, :cond_12

    .line 557
    .line 558
    :goto_9
    sget-object v2, Lyt/h;->u:Lst/a;

    .line 559
    .line 560
    const-string v4, "Unable to process the PerfMetric (%s) due to missing or invalid values. See earlier log statements for additional information on the specific missing/invalid values."

    .line 561
    .line 562
    invoke-static {v0}, Lyt/h;->a(Lau/u;)Ljava/lang/String;

    .line 563
    .line 564
    .line 565
    move-result-object v5

    .line 566
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 567
    .line 568
    .line 569
    move-result-object v5

    .line 570
    invoke-virtual {v2, v4, v5}, Lst/a;->g(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 571
    .line 572
    .line 573
    goto/16 :goto_8

    .line 574
    .line 575
    :cond_13
    iget-object v2, v1, Lyt/h;->o:Lyt/d;

    .line 576
    .line 577
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 578
    .line 579
    .line 580
    invoke-virtual {v0}, Lau/t;->d()Z

    .line 581
    .line 582
    .line 583
    move-result v5

    .line 584
    const-wide/high16 v7, 0x3ff0000000000000L    # 1.0

    .line 585
    .line 586
    const-wide v9, 0x3f50624dd2f1a9fcL    # 0.001

    .line 587
    .line 588
    .line 589
    .line 590
    .line 591
    if-eqz v5, :cond_19

    .line 592
    .line 593
    iget-object v5, v2, Lyt/d;->a:Lqt/a;

    .line 594
    .line 595
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 596
    .line 597
    .line 598
    const-class v11, Lqt/u;

    .line 599
    .line 600
    monitor-enter v11

    .line 601
    :try_start_1
    sget-object v12, Lqt/u;->a:Lqt/u;

    .line 602
    .line 603
    if-nez v12, :cond_14

    .line 604
    .line 605
    new-instance v12, Lqt/u;

    .line 606
    .line 607
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 608
    .line 609
    .line 610
    sput-object v12, Lqt/u;->a:Lqt/u;

    .line 611
    .line 612
    goto :goto_a

    .line 613
    :catchall_0
    move-exception v0

    .line 614
    goto/16 :goto_c

    .line 615
    .line 616
    :cond_14
    :goto_a
    sget-object v12, Lqt/u;->a:Lqt/u;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 617
    .line 618
    monitor-exit v11

    .line 619
    iget-object v11, v5, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 620
    .line 621
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 622
    .line 623
    .line 624
    const-string v13, "fpr_vc_trace_sampling_rate"

    .line 625
    .line 626
    invoke-virtual {v11, v13}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getDouble(Ljava/lang/String;)Lzt/d;

    .line 627
    .line 628
    .line 629
    move-result-object v11

    .line 630
    invoke-virtual {v11}, Lzt/d;->b()Z

    .line 631
    .line 632
    .line 633
    move-result v13

    .line 634
    if-eqz v13, :cond_15

    .line 635
    .line 636
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 637
    .line 638
    .line 639
    move-result-object v13

    .line 640
    check-cast v13, Ljava/lang/Double;

    .line 641
    .line 642
    invoke-virtual {v13}, Ljava/lang/Double;->doubleValue()D

    .line 643
    .line 644
    .line 645
    move-result-wide v13

    .line 646
    invoke-static {v13, v14}, Lqt/a;->p(D)Z

    .line 647
    .line 648
    .line 649
    move-result v13

    .line 650
    if-eqz v13, :cond_15

    .line 651
    .line 652
    iget-object v5, v5, Lqt/a;->c:Lqt/v;

    .line 653
    .line 654
    const-string v12, "com.google.firebase.perf.TraceSamplingRate"

    .line 655
    .line 656
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 657
    .line 658
    .line 659
    move-result-object v13

    .line 660
    check-cast v13, Ljava/lang/Double;

    .line 661
    .line 662
    invoke-virtual {v13}, Ljava/lang/Double;->doubleValue()D

    .line 663
    .line 664
    .line 665
    move-result-wide v13

    .line 666
    invoke-virtual {v5, v13, v14, v12}, Lqt/v;->d(DLjava/lang/String;)V

    .line 667
    .line 668
    .line 669
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 670
    .line 671
    .line 672
    move-result-object v5

    .line 673
    check-cast v5, Ljava/lang/Double;

    .line 674
    .line 675
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 676
    .line 677
    .line 678
    move-result-wide v11

    .line 679
    goto :goto_b

    .line 680
    :cond_15
    invoke-virtual {v5, v12}, Lqt/a;->b(Ljp/fg;)Lzt/d;

    .line 681
    .line 682
    .line 683
    move-result-object v11

    .line 684
    invoke-virtual {v11}, Lzt/d;->b()Z

    .line 685
    .line 686
    .line 687
    move-result v12

    .line 688
    if-eqz v12, :cond_16

    .line 689
    .line 690
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 691
    .line 692
    .line 693
    move-result-object v12

    .line 694
    check-cast v12, Ljava/lang/Double;

    .line 695
    .line 696
    invoke-virtual {v12}, Ljava/lang/Double;->doubleValue()D

    .line 697
    .line 698
    .line 699
    move-result-wide v12

    .line 700
    invoke-static {v12, v13}, Lqt/a;->p(D)Z

    .line 701
    .line 702
    .line 703
    move-result v12

    .line 704
    if-eqz v12, :cond_16

    .line 705
    .line 706
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 707
    .line 708
    .line 709
    move-result-object v5

    .line 710
    check-cast v5, Ljava/lang/Double;

    .line 711
    .line 712
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 713
    .line 714
    .line 715
    move-result-wide v11

    .line 716
    goto :goto_b

    .line 717
    :cond_16
    iget-object v5, v5, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 718
    .line 719
    invoke-virtual {v5}, Lcom/google/firebase/perf/config/RemoteConfigManager;->isLastFetchFailed()Z

    .line 720
    .line 721
    .line 722
    move-result v5

    .line 723
    if-eqz v5, :cond_17

    .line 724
    .line 725
    move-wide v11, v9

    .line 726
    goto :goto_b

    .line 727
    :cond_17
    move-wide v11, v7

    .line 728
    :goto_b
    iget-wide v13, v2, Lyt/d;->b:D

    .line 729
    .line 730
    cmpg-double v5, v13, v11

    .line 731
    .line 732
    if-gez v5, :cond_18

    .line 733
    .line 734
    goto :goto_d

    .line 735
    :cond_18
    invoke-virtual {v0}, Lau/t;->e()Lau/a0;

    .line 736
    .line 737
    .line 738
    move-result-object v5

    .line 739
    invoke-virtual {v5}, Lau/a0;->I()Lcom/google/protobuf/t;

    .line 740
    .line 741
    .line 742
    move-result-object v5

    .line 743
    invoke-static {v5}, Lyt/d;->a(Lcom/google/protobuf/t;)Z

    .line 744
    .line 745
    .line 746
    move-result v5

    .line 747
    if-nez v5, :cond_19

    .line 748
    .line 749
    goto/16 :goto_14

    .line 750
    .line 751
    :goto_c
    :try_start_2
    monitor-exit v11
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 752
    throw v0

    .line 753
    :cond_19
    :goto_d
    invoke-virtual {v0}, Lau/t;->d()Z

    .line 754
    .line 755
    .line 756
    move-result v5

    .line 757
    if-eqz v5, :cond_1f

    .line 758
    .line 759
    invoke-virtual {v0}, Lau/t;->e()Lau/a0;

    .line 760
    .line 761
    .line 762
    move-result-object v5

    .line 763
    invoke-virtual {v5}, Lau/a0;->H()Ljava/lang/String;

    .line 764
    .line 765
    .line 766
    move-result-object v5

    .line 767
    const-string v11, "_st_"

    .line 768
    .line 769
    invoke-virtual {v5, v11}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 770
    .line 771
    .line 772
    move-result v5

    .line 773
    if-eqz v5, :cond_1f

    .line 774
    .line 775
    invoke-virtual {v0}, Lau/t;->e()Lau/a0;

    .line 776
    .line 777
    .line 778
    move-result-object v5

    .line 779
    invoke-virtual {v5}, Lau/a0;->B()Z

    .line 780
    .line 781
    .line 782
    move-result v5

    .line 783
    if-eqz v5, :cond_1f

    .line 784
    .line 785
    iget-object v5, v2, Lyt/d;->a:Lqt/a;

    .line 786
    .line 787
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 788
    .line 789
    .line 790
    const-class v11, Lqt/e;

    .line 791
    .line 792
    monitor-enter v11

    .line 793
    :try_start_3
    sget-object v12, Lqt/e;->a:Lqt/e;

    .line 794
    .line 795
    if-nez v12, :cond_1a

    .line 796
    .line 797
    new-instance v12, Lqt/e;

    .line 798
    .line 799
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 800
    .line 801
    .line 802
    sput-object v12, Lqt/e;->a:Lqt/e;

    .line 803
    .line 804
    goto :goto_e

    .line 805
    :catchall_1
    move-exception v0

    .line 806
    goto/16 :goto_10

    .line 807
    .line 808
    :cond_1a
    :goto_e
    sget-object v12, Lqt/e;->a:Lqt/e;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 809
    .line 810
    monitor-exit v11

    .line 811
    invoke-virtual {v5, v12}, Lqt/a;->i(Ljp/fg;)Lzt/d;

    .line 812
    .line 813
    .line 814
    move-result-object v11

    .line 815
    invoke-virtual {v11}, Lzt/d;->b()Z

    .line 816
    .line 817
    .line 818
    move-result v13

    .line 819
    if-eqz v13, :cond_1b

    .line 820
    .line 821
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 822
    .line 823
    .line 824
    move-result-object v11

    .line 825
    check-cast v11, Ljava/lang/Double;

    .line 826
    .line 827
    invoke-virtual {v11}, Ljava/lang/Double;->doubleValue()D

    .line 828
    .line 829
    .line 830
    move-result-wide v13

    .line 831
    const-wide/high16 v15, 0x4059000000000000L    # 100.0

    .line 832
    .line 833
    div-double/2addr v13, v15

    .line 834
    invoke-static {v13, v14}, Lqt/a;->p(D)Z

    .line 835
    .line 836
    .line 837
    move-result v11

    .line 838
    if-eqz v11, :cond_1b

    .line 839
    .line 840
    goto :goto_f

    .line 841
    :cond_1b
    iget-object v11, v5, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 842
    .line 843
    const-string v13, "fpr_vc_fragment_sampling_rate"

    .line 844
    .line 845
    invoke-virtual {v11, v13}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getDouble(Ljava/lang/String;)Lzt/d;

    .line 846
    .line 847
    .line 848
    move-result-object v11

    .line 849
    invoke-virtual {v11}, Lzt/d;->b()Z

    .line 850
    .line 851
    .line 852
    move-result v13

    .line 853
    if-eqz v13, :cond_1c

    .line 854
    .line 855
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 856
    .line 857
    .line 858
    move-result-object v13

    .line 859
    check-cast v13, Ljava/lang/Double;

    .line 860
    .line 861
    invoke-virtual {v13}, Ljava/lang/Double;->doubleValue()D

    .line 862
    .line 863
    .line 864
    move-result-wide v13

    .line 865
    invoke-static {v13, v14}, Lqt/a;->p(D)Z

    .line 866
    .line 867
    .line 868
    move-result v13

    .line 869
    if-eqz v13, :cond_1c

    .line 870
    .line 871
    iget-object v5, v5, Lqt/a;->c:Lqt/v;

    .line 872
    .line 873
    const-string v12, "com.google.firebase.perf.FragmentSamplingRate"

    .line 874
    .line 875
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 876
    .line 877
    .line 878
    move-result-object v13

    .line 879
    check-cast v13, Ljava/lang/Double;

    .line 880
    .line 881
    invoke-virtual {v13}, Ljava/lang/Double;->doubleValue()D

    .line 882
    .line 883
    .line 884
    move-result-wide v13

    .line 885
    invoke-virtual {v5, v13, v14, v12}, Lqt/v;->d(DLjava/lang/String;)V

    .line 886
    .line 887
    .line 888
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 889
    .line 890
    .line 891
    move-result-object v5

    .line 892
    check-cast v5, Ljava/lang/Double;

    .line 893
    .line 894
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 895
    .line 896
    .line 897
    move-result-wide v13

    .line 898
    goto :goto_f

    .line 899
    :cond_1c
    invoke-virtual {v5, v12}, Lqt/a;->b(Ljp/fg;)Lzt/d;

    .line 900
    .line 901
    .line 902
    move-result-object v5

    .line 903
    invoke-virtual {v5}, Lzt/d;->b()Z

    .line 904
    .line 905
    .line 906
    move-result v11

    .line 907
    if-eqz v11, :cond_1d

    .line 908
    .line 909
    invoke-virtual {v5}, Lzt/d;->a()Ljava/lang/Object;

    .line 910
    .line 911
    .line 912
    move-result-object v11

    .line 913
    check-cast v11, Ljava/lang/Double;

    .line 914
    .line 915
    invoke-virtual {v11}, Ljava/lang/Double;->doubleValue()D

    .line 916
    .line 917
    .line 918
    move-result-wide v11

    .line 919
    invoke-static {v11, v12}, Lqt/a;->p(D)Z

    .line 920
    .line 921
    .line 922
    move-result v11

    .line 923
    if-eqz v11, :cond_1d

    .line 924
    .line 925
    invoke-virtual {v5}, Lzt/d;->a()Ljava/lang/Object;

    .line 926
    .line 927
    .line 928
    move-result-object v5

    .line 929
    check-cast v5, Ljava/lang/Double;

    .line 930
    .line 931
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 932
    .line 933
    .line 934
    move-result-wide v13

    .line 935
    goto :goto_f

    .line 936
    :cond_1d
    const-wide/16 v13, 0x0

    .line 937
    .line 938
    :goto_f
    iget-wide v11, v2, Lyt/d;->c:D

    .line 939
    .line 940
    cmpg-double v5, v11, v13

    .line 941
    .line 942
    if-gez v5, :cond_1e

    .line 943
    .line 944
    goto :goto_11

    .line 945
    :cond_1e
    invoke-virtual {v0}, Lau/t;->e()Lau/a0;

    .line 946
    .line 947
    .line 948
    move-result-object v5

    .line 949
    invoke-virtual {v5}, Lau/a0;->I()Lcom/google/protobuf/t;

    .line 950
    .line 951
    .line 952
    move-result-object v5

    .line 953
    invoke-static {v5}, Lyt/d;->a(Lcom/google/protobuf/t;)Z

    .line 954
    .line 955
    .line 956
    move-result v5

    .line 957
    if-nez v5, :cond_1f

    .line 958
    .line 959
    goto/16 :goto_14

    .line 960
    .line 961
    :goto_10
    :try_start_4
    monitor-exit v11
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 962
    throw v0

    .line 963
    :cond_1f
    :goto_11
    invoke-virtual {v0}, Lau/t;->b()Z

    .line 964
    .line 965
    .line 966
    move-result v5

    .line 967
    if-eqz v5, :cond_25

    .line 968
    .line 969
    iget-object v5, v2, Lyt/d;->a:Lqt/a;

    .line 970
    .line 971
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 972
    .line 973
    .line 974
    const-class v11, Lqt/i;

    .line 975
    .line 976
    monitor-enter v11

    .line 977
    :try_start_5
    sget-object v12, Lqt/i;->a:Lqt/i;

    .line 978
    .line 979
    if-nez v12, :cond_20

    .line 980
    .line 981
    new-instance v12, Lqt/i;

    .line 982
    .line 983
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 984
    .line 985
    .line 986
    sput-object v12, Lqt/i;->a:Lqt/i;

    .line 987
    .line 988
    goto :goto_12

    .line 989
    :catchall_2
    move-exception v0

    .line 990
    goto/16 :goto_15

    .line 991
    .line 992
    :cond_20
    :goto_12
    sget-object v12, Lqt/i;->a:Lqt/i;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 993
    .line 994
    monitor-exit v11

    .line 995
    iget-object v11, v5, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 996
    .line 997
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 998
    .line 999
    .line 1000
    const-string v13, "fpr_vc_network_request_sampling_rate"

    .line 1001
    .line 1002
    invoke-virtual {v11, v13}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getDouble(Ljava/lang/String;)Lzt/d;

    .line 1003
    .line 1004
    .line 1005
    move-result-object v11

    .line 1006
    invoke-virtual {v11}, Lzt/d;->b()Z

    .line 1007
    .line 1008
    .line 1009
    move-result v13

    .line 1010
    if-eqz v13, :cond_21

    .line 1011
    .line 1012
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 1013
    .line 1014
    .line 1015
    move-result-object v13

    .line 1016
    check-cast v13, Ljava/lang/Double;

    .line 1017
    .line 1018
    invoke-virtual {v13}, Ljava/lang/Double;->doubleValue()D

    .line 1019
    .line 1020
    .line 1021
    move-result-wide v13

    .line 1022
    invoke-static {v13, v14}, Lqt/a;->p(D)Z

    .line 1023
    .line 1024
    .line 1025
    move-result v13

    .line 1026
    if-eqz v13, :cond_21

    .line 1027
    .line 1028
    iget-object v5, v5, Lqt/a;->c:Lqt/v;

    .line 1029
    .line 1030
    const-string v7, "com.google.firebase.perf.NetworkRequestSamplingRate"

    .line 1031
    .line 1032
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 1033
    .line 1034
    .line 1035
    move-result-object v8

    .line 1036
    check-cast v8, Ljava/lang/Double;

    .line 1037
    .line 1038
    invoke-virtual {v8}, Ljava/lang/Double;->doubleValue()D

    .line 1039
    .line 1040
    .line 1041
    move-result-wide v8

    .line 1042
    invoke-virtual {v5, v8, v9, v7}, Lqt/v;->d(DLjava/lang/String;)V

    .line 1043
    .line 1044
    .line 1045
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 1046
    .line 1047
    .line 1048
    move-result-object v5

    .line 1049
    check-cast v5, Ljava/lang/Double;

    .line 1050
    .line 1051
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 1052
    .line 1053
    .line 1054
    move-result-wide v7

    .line 1055
    goto :goto_13

    .line 1056
    :cond_21
    invoke-virtual {v5, v12}, Lqt/a;->b(Ljp/fg;)Lzt/d;

    .line 1057
    .line 1058
    .line 1059
    move-result-object v11

    .line 1060
    invoke-virtual {v11}, Lzt/d;->b()Z

    .line 1061
    .line 1062
    .line 1063
    move-result v12

    .line 1064
    if-eqz v12, :cond_22

    .line 1065
    .line 1066
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v12

    .line 1070
    check-cast v12, Ljava/lang/Double;

    .line 1071
    .line 1072
    invoke-virtual {v12}, Ljava/lang/Double;->doubleValue()D

    .line 1073
    .line 1074
    .line 1075
    move-result-wide v12

    .line 1076
    invoke-static {v12, v13}, Lqt/a;->p(D)Z

    .line 1077
    .line 1078
    .line 1079
    move-result v12

    .line 1080
    if-eqz v12, :cond_22

    .line 1081
    .line 1082
    invoke-virtual {v11}, Lzt/d;->a()Ljava/lang/Object;

    .line 1083
    .line 1084
    .line 1085
    move-result-object v5

    .line 1086
    check-cast v5, Ljava/lang/Double;

    .line 1087
    .line 1088
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 1089
    .line 1090
    .line 1091
    move-result-wide v7

    .line 1092
    goto :goto_13

    .line 1093
    :cond_22
    iget-object v5, v5, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 1094
    .line 1095
    invoke-virtual {v5}, Lcom/google/firebase/perf/config/RemoteConfigManager;->isLastFetchFailed()Z

    .line 1096
    .line 1097
    .line 1098
    move-result v5

    .line 1099
    if-eqz v5, :cond_23

    .line 1100
    .line 1101
    move-wide v7, v9

    .line 1102
    :cond_23
    :goto_13
    iget-wide v9, v2, Lyt/d;->b:D

    .line 1103
    .line 1104
    cmpg-double v2, v9, v7

    .line 1105
    .line 1106
    if-gez v2, :cond_24

    .line 1107
    .line 1108
    goto :goto_16

    .line 1109
    :cond_24
    invoke-virtual {v0}, Lau/t;->c()Lau/r;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v2

    .line 1113
    invoke-virtual {v2}, Lau/r;->J()Lcom/google/protobuf/t;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v2

    .line 1117
    invoke-static {v2}, Lyt/d;->a(Lcom/google/protobuf/t;)Z

    .line 1118
    .line 1119
    .line 1120
    move-result v2

    .line 1121
    if-nez v2, :cond_25

    .line 1122
    .line 1123
    :goto_14
    invoke-virtual {v1, v0}, Lyt/h;->b(Lau/t;)V

    .line 1124
    .line 1125
    .line 1126
    sget-object v2, Lyt/h;->u:Lst/a;

    .line 1127
    .line 1128
    const-string v4, "Event dropped due to device sampling - %s"

    .line 1129
    .line 1130
    invoke-static {v0}, Lyt/h;->a(Lau/u;)Ljava/lang/String;

    .line 1131
    .line 1132
    .line 1133
    move-result-object v5

    .line 1134
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 1135
    .line 1136
    .line 1137
    move-result-object v5

    .line 1138
    invoke-virtual {v2, v4, v5}, Lst/a;->e(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 1139
    .line 1140
    .line 1141
    goto/16 :goto_8

    .line 1142
    .line 1143
    :goto_15
    :try_start_6
    monitor-exit v11
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 1144
    throw v0

    .line 1145
    :cond_25
    :goto_16
    iget-object v2, v1, Lyt/h;->o:Lyt/d;

    .line 1146
    .line 1147
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1148
    .line 1149
    .line 1150
    invoke-virtual {v0}, Lau/t;->d()Z

    .line 1151
    .line 1152
    .line 1153
    move-result v5

    .line 1154
    if-eqz v5, :cond_27

    .line 1155
    .line 1156
    invoke-virtual {v0}, Lau/t;->e()Lau/a0;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v5

    .line 1160
    invoke-virtual {v5}, Lau/a0;->H()Ljava/lang/String;

    .line 1161
    .line 1162
    .line 1163
    move-result-object v5

    .line 1164
    const-string v7, "_fs"

    .line 1165
    .line 1166
    invoke-virtual {v5, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1167
    .line 1168
    .line 1169
    move-result v5

    .line 1170
    if-nez v5, :cond_26

    .line 1171
    .line 1172
    invoke-virtual {v0}, Lau/t;->e()Lau/a0;

    .line 1173
    .line 1174
    .line 1175
    move-result-object v5

    .line 1176
    invoke-virtual {v5}, Lau/a0;->H()Ljava/lang/String;

    .line 1177
    .line 1178
    .line 1179
    move-result-object v5

    .line 1180
    const-string v7, "_bs"

    .line 1181
    .line 1182
    invoke-virtual {v5, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1183
    .line 1184
    .line 1185
    move-result v5

    .line 1186
    if-eqz v5, :cond_27

    .line 1187
    .line 1188
    :cond_26
    invoke-virtual {v0}, Lau/t;->e()Lau/a0;

    .line 1189
    .line 1190
    .line 1191
    move-result-object v5

    .line 1192
    invoke-virtual {v5}, Lau/a0;->C()I

    .line 1193
    .line 1194
    .line 1195
    move-result v5

    .line 1196
    if-lez v5, :cond_27

    .line 1197
    .line 1198
    goto :goto_17

    .line 1199
    :cond_27
    invoke-virtual {v0}, Lau/t;->a()Z

    .line 1200
    .line 1201
    .line 1202
    move-result v5

    .line 1203
    if-eqz v5, :cond_28

    .line 1204
    .line 1205
    :goto_17
    move v2, v3

    .line 1206
    goto :goto_19

    .line 1207
    :cond_28
    invoke-virtual {v0}, Lau/t;->b()Z

    .line 1208
    .line 1209
    .line 1210
    move-result v5

    .line 1211
    if-eqz v5, :cond_29

    .line 1212
    .line 1213
    iget-object v2, v2, Lyt/d;->e:Lyt/c;

    .line 1214
    .line 1215
    invoke-virtual {v2}, Lyt/c;->b()Z

    .line 1216
    .line 1217
    .line 1218
    move-result v2

    .line 1219
    :goto_18
    xor-int/2addr v2, v4

    .line 1220
    goto :goto_19

    .line 1221
    :cond_29
    invoke-virtual {v0}, Lau/t;->d()Z

    .line 1222
    .line 1223
    .line 1224
    move-result v5

    .line 1225
    if-eqz v5, :cond_2a

    .line 1226
    .line 1227
    iget-object v2, v2, Lyt/d;->d:Lyt/c;

    .line 1228
    .line 1229
    invoke-virtual {v2}, Lyt/c;->b()Z

    .line 1230
    .line 1231
    .line 1232
    move-result v2

    .line 1233
    goto :goto_18

    .line 1234
    :cond_2a
    move v2, v4

    .line 1235
    :goto_19
    if-eqz v2, :cond_2b

    .line 1236
    .line 1237
    invoke-virtual {v1, v0}, Lyt/h;->b(Lau/t;)V

    .line 1238
    .line 1239
    .line 1240
    sget-object v2, Lyt/h;->u:Lst/a;

    .line 1241
    .line 1242
    const-string v4, "Rate limited (per device) - %s"

    .line 1243
    .line 1244
    invoke-static {v0}, Lyt/h;->a(Lau/u;)Ljava/lang/String;

    .line 1245
    .line 1246
    .line 1247
    move-result-object v5

    .line 1248
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 1249
    .line 1250
    .line 1251
    move-result-object v5

    .line 1252
    invoke-virtual {v2, v4, v5}, Lst/a;->e(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 1253
    .line 1254
    .line 1255
    goto/16 :goto_8

    .line 1256
    .line 1257
    :cond_2b
    :goto_1a
    if-eqz v4, :cond_31

    .line 1258
    .line 1259
    sget-object v2, Lyt/h;->u:Lst/a;

    .line 1260
    .line 1261
    invoke-virtual {v0}, Lau/t;->d()Z

    .line 1262
    .line 1263
    .line 1264
    move-result v3

    .line 1265
    if-eqz v3, :cond_2d

    .line 1266
    .line 1267
    const-string v3, "Logging %s. In a minute, visit the Firebase console to view your data: %s"

    .line 1268
    .line 1269
    invoke-static {v0}, Lyt/h;->a(Lau/u;)Ljava/lang/String;

    .line 1270
    .line 1271
    .line 1272
    move-result-object v4

    .line 1273
    invoke-virtual {v0}, Lau/t;->e()Lau/a0;

    .line 1274
    .line 1275
    .line 1276
    move-result-object v5

    .line 1277
    const-string v7, "?utm_source=perf-android-sdk&utm_medium=android-ide"

    .line 1278
    .line 1279
    invoke-virtual {v5}, Lau/a0;->H()Ljava/lang/String;

    .line 1280
    .line 1281
    .line 1282
    move-result-object v5

    .line 1283
    const-string v8, "_st_"

    .line 1284
    .line 1285
    invoke-virtual {v5, v8}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 1286
    .line 1287
    .line 1288
    move-result v8

    .line 1289
    if-eqz v8, :cond_2c

    .line 1290
    .line 1291
    iget-object v8, v1, Lyt/h;->s:Ljava/lang/String;

    .line 1292
    .line 1293
    iget-object v9, v1, Lyt/h;->r:Ljava/lang/String;

    .line 1294
    .line 1295
    invoke-static {v8, v9}, Lkp/q8;->c(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v8

    .line 1299
    const-string v9, "/troubleshooting/trace/SCREEN_TRACE/"

    .line 1300
    .line 1301
    invoke-static {v8, v9, v5, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1302
    .line 1303
    .line 1304
    move-result-object v5

    .line 1305
    goto :goto_1b

    .line 1306
    :cond_2c
    iget-object v8, v1, Lyt/h;->s:Ljava/lang/String;

    .line 1307
    .line 1308
    iget-object v9, v1, Lyt/h;->r:Ljava/lang/String;

    .line 1309
    .line 1310
    invoke-static {v8, v9}, Lkp/q8;->c(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1311
    .line 1312
    .line 1313
    move-result-object v8

    .line 1314
    const-string v9, "/troubleshooting/trace/DURATION_TRACE/"

    .line 1315
    .line 1316
    invoke-static {v8, v9, v5, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1317
    .line 1318
    .line 1319
    move-result-object v5

    .line 1320
    :goto_1b
    filled-new-array {v4, v5}, [Ljava/lang/Object;

    .line 1321
    .line 1322
    .line 1323
    move-result-object v4

    .line 1324
    invoke-virtual {v2, v3, v4}, Lst/a;->e(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 1325
    .line 1326
    .line 1327
    goto :goto_1c

    .line 1328
    :cond_2d
    const-string v3, "Logging %s"

    .line 1329
    .line 1330
    invoke-static {v0}, Lyt/h;->a(Lau/u;)Ljava/lang/String;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v4

    .line 1334
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 1335
    .line 1336
    .line 1337
    move-result-object v4

    .line 1338
    invoke-virtual {v2, v3, v4}, Lst/a;->e(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 1339
    .line 1340
    .line 1341
    :goto_1c
    iget-object v1, v1, Lyt/h;->k:Lyt/a;

    .line 1342
    .line 1343
    sget-object v2, Lyt/a;->d:Lst/a;

    .line 1344
    .line 1345
    iget-object v3, v1, Lyt/a;->c:Lrn/q;

    .line 1346
    .line 1347
    const/16 v4, 0x19

    .line 1348
    .line 1349
    if-nez v3, :cond_2f

    .line 1350
    .line 1351
    iget-object v3, v1, Lyt/a;->b:Lgt/b;

    .line 1352
    .line 1353
    invoke-interface {v3}, Lgt/b;->get()Ljava/lang/Object;

    .line 1354
    .line 1355
    .line 1356
    move-result-object v3

    .line 1357
    check-cast v3, Lon/f;

    .line 1358
    .line 1359
    if-eqz v3, :cond_2e

    .line 1360
    .line 1361
    iget-object v5, v1, Lyt/a;->a:Ljava/lang/String;

    .line 1362
    .line 1363
    const-string v7, "proto"

    .line 1364
    .line 1365
    new-instance v8, Lon/c;

    .line 1366
    .line 1367
    invoke-direct {v8, v7}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 1368
    .line 1369
    .line 1370
    new-instance v7, Lt0/c;

    .line 1371
    .line 1372
    invoke-direct {v7, v4}, Lt0/c;-><init>(I)V

    .line 1373
    .line 1374
    .line 1375
    check-cast v3, Lrn/p;

    .line 1376
    .line 1377
    invoke-virtual {v3, v5, v8, v7}, Lrn/p;->a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;

    .line 1378
    .line 1379
    .line 1380
    move-result-object v3

    .line 1381
    iput-object v3, v1, Lyt/a;->c:Lrn/q;

    .line 1382
    .line 1383
    goto :goto_1d

    .line 1384
    :cond_2e
    const-string v3, "Flg TransportFactory is not available at the moment"

    .line 1385
    .line 1386
    invoke-virtual {v2, v3}, Lst/a;->f(Ljava/lang/String;)V

    .line 1387
    .line 1388
    .line 1389
    :cond_2f
    :goto_1d
    iget-object v1, v1, Lyt/a;->c:Lrn/q;

    .line 1390
    .line 1391
    if-eqz v1, :cond_30

    .line 1392
    .line 1393
    new-instance v2, Lon/a;

    .line 1394
    .line 1395
    sget-object v3, Lon/d;->d:Lon/d;

    .line 1396
    .line 1397
    invoke-direct {v2, v0, v3, v6}, Lon/a;-><init>(Ljava/lang/Object;Lon/d;Lon/b;)V

    .line 1398
    .line 1399
    .line 1400
    new-instance v0, Lj9/d;

    .line 1401
    .line 1402
    invoke-direct {v0, v4}, Lj9/d;-><init>(I)V

    .line 1403
    .line 1404
    .line 1405
    invoke-virtual {v1, v2, v0}, Lrn/q;->a(Lon/a;Lon/g;)V

    .line 1406
    .line 1407
    .line 1408
    goto :goto_1e

    .line 1409
    :cond_30
    const-string v0, "Unable to dispatch event because Flg Transport is not available"

    .line 1410
    .line 1411
    invoke-virtual {v2, v0}, Lst/a;->f(Ljava/lang/String;)V

    .line 1412
    .line 1413
    .line 1414
    :goto_1e
    invoke-static {}, Lcom/google/firebase/perf/session/SessionManager;->getInstance()Lcom/google/firebase/perf/session/SessionManager;

    .line 1415
    .line 1416
    .line 1417
    move-result-object v0

    .line 1418
    invoke-virtual {v0}, Lcom/google/firebase/perf/session/SessionManager;->stopGaugeCollectionIfSessionRunningTooLong()V

    .line 1419
    .line 1420
    .line 1421
    :cond_31
    return-void
.end method

.method public final onUpdateAppState(Lau/i;)V
    .locals 1

    .line 1
    sget-object v0, Lau/i;->f:Lau/i;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 p1, 0x0

    .line 8
    :goto_0
    iput-boolean p1, p0, Lyt/h;->t:Z

    .line 9
    .line 10
    iget-object p1, p0, Lyt/h;->f:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    new-instance p1, Lyt/e;

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-direct {p1, p0, v0}, Lyt/e;-><init>(Lyt/h;I)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lyt/h;->l:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method
