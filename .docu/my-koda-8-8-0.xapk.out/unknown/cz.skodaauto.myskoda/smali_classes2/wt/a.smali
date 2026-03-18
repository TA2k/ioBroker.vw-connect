.class public final Lwt/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lwt/a;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lzt/h;

.field public f:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltt/f;

    .line 2
    .line 3
    const/16 v1, 0x12

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ltt/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lwt/a;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 2

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 7
    iput-boolean v0, p0, Lwt/a;->f:Z

    .line 8
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lwt/a;->d:Ljava/lang/String;

    .line 9
    invoke-virtual {p1}, Landroid/os/Parcel;->readByte()B

    move-result v1

    if-eqz v1, :cond_0

    const/4 v0, 0x1

    :cond_0
    iput-boolean v0, p0, Lwt/a;->f:Z

    .line 10
    const-class v0, Lzt/h;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    move-result-object p1

    check-cast p1, Lzt/h;

    iput-object p1, p0, Lwt/a;->e:Lzt/h;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;La61/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p2, 0x0

    .line 2
    iput-boolean p2, p0, Lwt/a;->f:Z

    .line 3
    iput-object p1, p0, Lwt/a;->d:Ljava/lang/String;

    .line 4
    new-instance p1, Lzt/h;

    invoke-direct {p1}, Lzt/h;-><init>()V

    .line 5
    iput-object p1, p0, Lwt/a;->e:Lzt/h;

    return-void
.end method

.method public static i(Ljava/util/List;)[Lau/w;
    .locals 8

    .line 1
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    new-array v0, v0, [Lau/w;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    check-cast v2, Lwt/a;

    .line 21
    .line 22
    invoke-virtual {v2}, Lwt/a;->h()Lau/w;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    const/4 v3, 0x1

    .line 27
    move v5, v1

    .line 28
    move v4, v3

    .line 29
    :goto_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    if-ge v4, v6, :cond_2

    .line 34
    .line 35
    invoke-interface {p0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v6

    .line 39
    check-cast v6, Lwt/a;

    .line 40
    .line 41
    invoke-virtual {v6}, Lwt/a;->h()Lau/w;

    .line 42
    .line 43
    .line 44
    move-result-object v6

    .line 45
    if-nez v5, :cond_1

    .line 46
    .line 47
    invoke-interface {p0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    check-cast v7, Lwt/a;

    .line 52
    .line 53
    iget-boolean v7, v7, Lwt/a;->f:Z

    .line 54
    .line 55
    if-eqz v7, :cond_1

    .line 56
    .line 57
    aput-object v6, v0, v1

    .line 58
    .line 59
    aput-object v2, v0, v4

    .line 60
    .line 61
    move v5, v3

    .line 62
    goto :goto_1

    .line 63
    :cond_1
    aput-object v6, v0, v4

    .line 64
    .line 65
    :goto_1
    add-int/lit8 v4, v4, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    if-nez v5, :cond_3

    .line 69
    .line 70
    aput-object v2, v0, v1

    .line 71
    .line 72
    :cond_3
    return-object v0
.end method

.method public static j(Ljava/lang/String;)Lwt/a;
    .locals 9

    .line 1
    const-string v0, "-"

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    new-instance v0, Lwt/a;

    .line 10
    .line 11
    new-instance v1, La61/a;

    .line 12
    .line 13
    const/16 v2, 0x1c

    .line 14
    .line 15
    invoke-direct {v1, v2}, La61/a;-><init>(I)V

    .line 16
    .line 17
    .line 18
    invoke-direct {v0, p0, v1}, Lwt/a;-><init>(Ljava/lang/String;La61/a;)V

    .line 19
    .line 20
    .line 21
    invoke-static {}, Lqt/a;->e()Lqt/a;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0}, Lqt/a;->o()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_5

    .line 30
    .line 31
    invoke-static {}, Ljava/lang/Math;->random()D

    .line 32
    .line 33
    .line 34
    move-result-wide v1

    .line 35
    const-class v3, Lqt/r;

    .line 36
    .line 37
    monitor-enter v3

    .line 38
    :try_start_0
    sget-object v4, Lqt/r;->a:Lqt/r;

    .line 39
    .line 40
    if-nez v4, :cond_0

    .line 41
    .line 42
    new-instance v4, Lqt/r;

    .line 43
    .line 44
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 45
    .line 46
    .line 47
    sput-object v4, Lqt/r;->a:Lqt/r;

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catchall_0
    move-exception p0

    .line 51
    goto/16 :goto_2

    .line 52
    .line 53
    :cond_0
    :goto_0
    sget-object v4, Lqt/r;->a:Lqt/r;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 54
    .line 55
    monitor-exit v3

    .line 56
    invoke-virtual {p0, v4}, Lqt/a;->i(Ljp/fg;)Lzt/d;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    invoke-virtual {v3}, Lzt/d;->b()Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz v5, :cond_1

    .line 65
    .line 66
    invoke-virtual {v3}, Lzt/d;->a()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    check-cast v3, Ljava/lang/Double;

    .line 71
    .line 72
    invoke-virtual {v3}, Ljava/lang/Double;->doubleValue()D

    .line 73
    .line 74
    .line 75
    move-result-wide v5

    .line 76
    const-wide/high16 v7, 0x4059000000000000L    # 100.0

    .line 77
    .line 78
    div-double/2addr v5, v7

    .line 79
    invoke-static {v5, v6}, Lqt/a;->p(D)Z

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-eqz v3, :cond_1

    .line 84
    .line 85
    goto/16 :goto_1

    .line 86
    .line 87
    :cond_1
    iget-object v3, p0, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 88
    .line 89
    const-string v5, "fpr_vc_session_sampling_rate"

    .line 90
    .line 91
    invoke-virtual {v3, v5}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getDouble(Ljava/lang/String;)Lzt/d;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-virtual {v3}, Lzt/d;->b()Z

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    if-eqz v5, :cond_2

    .line 100
    .line 101
    invoke-virtual {v3}, Lzt/d;->a()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    check-cast v5, Ljava/lang/Double;

    .line 106
    .line 107
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 108
    .line 109
    .line 110
    move-result-wide v5

    .line 111
    invoke-static {v5, v6}, Lqt/a;->p(D)Z

    .line 112
    .line 113
    .line 114
    move-result v5

    .line 115
    if-eqz v5, :cond_2

    .line 116
    .line 117
    iget-object p0, p0, Lqt/a;->c:Lqt/v;

    .line 118
    .line 119
    const-string v4, "com.google.firebase.perf.SessionSamplingRate"

    .line 120
    .line 121
    invoke-virtual {v3}, Lzt/d;->a()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v5

    .line 125
    check-cast v5, Ljava/lang/Double;

    .line 126
    .line 127
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 128
    .line 129
    .line 130
    move-result-wide v5

    .line 131
    invoke-virtual {p0, v5, v6, v4}, Lqt/v;->d(DLjava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v3}, Lzt/d;->a()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    check-cast p0, Ljava/lang/Double;

    .line 139
    .line 140
    invoke-virtual {p0}, Ljava/lang/Double;->doubleValue()D

    .line 141
    .line 142
    .line 143
    move-result-wide v5

    .line 144
    goto :goto_1

    .line 145
    :cond_2
    invoke-virtual {p0, v4}, Lqt/a;->b(Ljp/fg;)Lzt/d;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    invoke-virtual {v3}, Lzt/d;->b()Z

    .line 150
    .line 151
    .line 152
    move-result v4

    .line 153
    if-eqz v4, :cond_3

    .line 154
    .line 155
    invoke-virtual {v3}, Lzt/d;->a()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v4

    .line 159
    check-cast v4, Ljava/lang/Double;

    .line 160
    .line 161
    invoke-virtual {v4}, Ljava/lang/Double;->doubleValue()D

    .line 162
    .line 163
    .line 164
    move-result-wide v4

    .line 165
    invoke-static {v4, v5}, Lqt/a;->p(D)Z

    .line 166
    .line 167
    .line 168
    move-result v4

    .line 169
    if-eqz v4, :cond_3

    .line 170
    .line 171
    invoke-virtual {v3}, Lzt/d;->a()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    check-cast p0, Ljava/lang/Double;

    .line 176
    .line 177
    invoke-virtual {p0}, Ljava/lang/Double;->doubleValue()D

    .line 178
    .line 179
    .line 180
    move-result-wide v5

    .line 181
    goto :goto_1

    .line 182
    :cond_3
    iget-object p0, p0, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 183
    .line 184
    invoke-virtual {p0}, Lcom/google/firebase/perf/config/RemoteConfigManager;->isLastFetchFailed()Z

    .line 185
    .line 186
    .line 187
    move-result p0

    .line 188
    if-eqz p0, :cond_4

    .line 189
    .line 190
    const-wide v5, 0x3ee4f8b588e368f1L    # 1.0E-5

    .line 191
    .line 192
    .line 193
    .line 194
    .line 195
    goto :goto_1

    .line 196
    :cond_4
    const-wide v5, 0x3f847ae147ae147bL    # 0.01

    .line 197
    .line 198
    .line 199
    .line 200
    .line 201
    :goto_1
    cmpg-double p0, v1, v5

    .line 202
    .line 203
    if-gez p0, :cond_5

    .line 204
    .line 205
    const/4 p0, 0x1

    .line 206
    goto :goto_3

    .line 207
    :goto_2
    :try_start_1
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 208
    throw p0

    .line 209
    :cond_5
    const/4 p0, 0x0

    .line 210
    :goto_3
    iput-boolean p0, v0, Lwt/a;->f:Z

    .line 211
    .line 212
    return-object v0
.end method


# virtual methods
.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final h()Lau/w;
    .locals 3

    .line 1
    invoke-static {}, Lau/w;->w()Lau/v;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 9
    .line 10
    check-cast v1, Lau/w;

    .line 11
    .line 12
    iget-object v2, p0, Lwt/a;->d:Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {v1, v2}, Lau/w;->s(Lau/w;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-boolean p0, p0, Lwt/a;->f:Z

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 22
    .line 23
    .line 24
    iget-object p0, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 25
    .line 26
    check-cast p0, Lau/w;

    .line 27
    .line 28
    invoke-static {p0}, Lau/w;->t(Lau/w;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    invoke-virtual {v0}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    check-cast p0, Lau/w;

    .line 36
    .line 37
    return-object p0
.end method

.method public final k()Z
    .locals 9

    .line 1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MICROSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    iget-object p0, p0, Lwt/a;->e:Lzt/h;

    .line 4
    .line 5
    invoke-virtual {p0}, Lzt/h;->j()J

    .line 6
    .line 7
    .line 8
    move-result-wide v1

    .line 9
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toMinutes(J)J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    invoke-static {}, Lqt/a;->e()Lqt/a;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    const-class v2, Lqt/o;

    .line 21
    .line 22
    monitor-enter v2

    .line 23
    :try_start_0
    sget-object v3, Lqt/o;->a:Lqt/o;

    .line 24
    .line 25
    if-nez v3, :cond_0

    .line 26
    .line 27
    new-instance v3, Lqt/o;

    .line 28
    .line 29
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    sput-object v3, Lqt/o;->a:Lqt/o;

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto/16 :goto_2

    .line 37
    .line 38
    :cond_0
    :goto_0
    sget-object v3, Lqt/o;->a:Lqt/o;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    monitor-exit v2

    .line 41
    invoke-virtual {p0, v3}, Lqt/a;->j(Ljp/fg;)Lzt/d;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-virtual {v2}, Lzt/d;->b()Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    const-wide/16 v5, 0x0

    .line 50
    .line 51
    if-eqz v4, :cond_1

    .line 52
    .line 53
    invoke-virtual {v2}, Lzt/d;->a()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    check-cast v4, Ljava/lang/Long;

    .line 58
    .line 59
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 60
    .line 61
    .line 62
    move-result-wide v7

    .line 63
    cmp-long v4, v7, v5

    .line 64
    .line 65
    if-lez v4, :cond_1

    .line 66
    .line 67
    invoke-virtual {v2}, Lzt/d;->a()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    check-cast p0, Ljava/lang/Long;

    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 74
    .line 75
    .line 76
    move-result-wide v2

    .line 77
    goto :goto_1

    .line 78
    :cond_1
    iget-object v2, p0, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 79
    .line 80
    const-string v4, "fpr_session_max_duration_min"

    .line 81
    .line 82
    invoke-virtual {v2, v4}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getLong(Ljava/lang/String;)Lzt/d;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {v2}, Lzt/d;->b()Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    if-eqz v4, :cond_2

    .line 91
    .line 92
    invoke-virtual {v2}, Lzt/d;->a()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    check-cast v4, Ljava/lang/Long;

    .line 97
    .line 98
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 99
    .line 100
    .line 101
    move-result-wide v7

    .line 102
    cmp-long v4, v7, v5

    .line 103
    .line 104
    if-lez v4, :cond_2

    .line 105
    .line 106
    iget-object p0, p0, Lqt/a;->c:Lqt/v;

    .line 107
    .line 108
    const-string v3, "com.google.firebase.perf.SessionsMaxDurationMinutes"

    .line 109
    .line 110
    invoke-virtual {v2}, Lzt/d;->a()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v4

    .line 114
    check-cast v4, Ljava/lang/Long;

    .line 115
    .line 116
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 117
    .line 118
    .line 119
    move-result-wide v4

    .line 120
    invoke-virtual {p0, v4, v5, v3}, Lqt/v;->e(JLjava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v2}, Lzt/d;->a()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    check-cast p0, Ljava/lang/Long;

    .line 128
    .line 129
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 130
    .line 131
    .line 132
    move-result-wide v2

    .line 133
    goto :goto_1

    .line 134
    :cond_2
    invoke-virtual {p0, v3}, Lqt/a;->c(Ljp/fg;)Lzt/d;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-virtual {p0}, Lzt/d;->b()Z

    .line 139
    .line 140
    .line 141
    move-result v2

    .line 142
    if-eqz v2, :cond_3

    .line 143
    .line 144
    invoke-virtual {p0}, Lzt/d;->a()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    check-cast v2, Ljava/lang/Long;

    .line 149
    .line 150
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 151
    .line 152
    .line 153
    move-result-wide v2

    .line 154
    cmp-long v2, v2, v5

    .line 155
    .line 156
    if-lez v2, :cond_3

    .line 157
    .line 158
    invoke-virtual {p0}, Lzt/d;->a()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    check-cast p0, Ljava/lang/Long;

    .line 163
    .line 164
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 165
    .line 166
    .line 167
    move-result-wide v2

    .line 168
    goto :goto_1

    .line 169
    :cond_3
    const-wide/16 v2, 0xf0

    .line 170
    .line 171
    :goto_1
    cmp-long p0, v0, v2

    .line 172
    .line 173
    if-lez p0, :cond_4

    .line 174
    .line 175
    const/4 p0, 0x1

    .line 176
    return p0

    .line 177
    :cond_4
    const/4 p0, 0x0

    .line 178
    return p0

    .line 179
    :goto_2
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 180
    throw p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    iget-object p2, p0, Lwt/a;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean p2, p0, Lwt/a;->f:Z

    .line 7
    .line 8
    int-to-byte p2, p2

    .line 9
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeByte(B)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lwt/a;->e:Lzt/h;

    .line 13
    .line 14
    const/4 p2, 0x0

    .line 15
    invoke-virtual {p1, p0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 16
    .line 17
    .line 18
    return-void
.end method
