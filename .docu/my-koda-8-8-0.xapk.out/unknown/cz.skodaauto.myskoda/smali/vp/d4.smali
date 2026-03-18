.class public final Lvp/d4;
.super Lvp/n1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final m:[Ljava/lang/String;

.field public static final n:[Ljava/lang/String;


# instance fields
.field public g:Ljava/security/SecureRandom;

.field public final h:Ljava/util/concurrent/atomic/AtomicLong;

.field public i:I

.field public j:Lga/a;

.field public k:Ljava/lang/Boolean;

.field public l:Ljava/lang/Integer;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "google_"

    .line 2
    .line 3
    const-string v1, "ga_"

    .line 4
    .line 5
    const-string v2, "firebase_"

    .line 6
    .line 7
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lvp/d4;->m:[Ljava/lang/String;

    .line 12
    .line 13
    const-string v0, "_err"

    .line 14
    .line 15
    filled-new-array {v0}, [Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lvp/d4;->n:[Ljava/lang/String;

    .line 20
    .line 21
    return-void
.end method

.method public constructor <init>(Lvp/g1;)V
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lvp/n1;-><init>(Lvp/g1;)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    iput-object p1, p0, Lvp/d4;->l:Ljava/lang/Integer;

    .line 6
    .line 7
    new-instance p1, Ljava/util/concurrent/atomic/AtomicLong;

    .line 8
    .line 9
    const-wide/16 v0, 0x0

    .line 10
    .line 11
    invoke-direct {p1, v0, v1}, Ljava/util/concurrent/atomic/AtomicLong;-><init>(J)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lvp/d4;->h:Ljava/util/concurrent/atomic/AtomicLong;

    .line 15
    .line 16
    return-void
.end method

.method public static E0(Landroid/os/Parcelable;)[B
    .locals 2

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x0

    .line 10
    :try_start_0
    invoke-interface {p0, v0, v1}, Landroid/os/Parcelable;->writeToParcel(Landroid/os/Parcel;I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Landroid/os/Parcel;->marshall()[B

    .line 14
    .line 15
    .line 16
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 23
    .line 24
    .line 25
    throw p0
.end method

.method public static P0(Ljava/util/List;)Ljava/util/ArrayList;
    .locals 6

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    new-instance p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_5

    .line 28
    .line 29
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Lvp/f;

    .line 34
    .line 35
    new-instance v2, Landroid/os/Bundle;

    .line 36
    .line 37
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 38
    .line 39
    .line 40
    iget-object v3, v1, Lvp/f;->d:Ljava/lang/String;

    .line 41
    .line 42
    const-string v4, "app_id"

    .line 43
    .line 44
    invoke-virtual {v2, v4, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-object v3, v1, Lvp/f;->e:Ljava/lang/String;

    .line 48
    .line 49
    const-string v4, "origin"

    .line 50
    .line 51
    invoke-virtual {v2, v4, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget-wide v3, v1, Lvp/f;->g:J

    .line 55
    .line 56
    const-string v5, "creation_timestamp"

    .line 57
    .line 58
    invoke-virtual {v2, v5, v3, v4}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 59
    .line 60
    .line 61
    iget-object v3, v1, Lvp/f;->f:Lvp/b4;

    .line 62
    .line 63
    iget-object v3, v3, Lvp/b4;->e:Ljava/lang/String;

    .line 64
    .line 65
    const-string v4, "name"

    .line 66
    .line 67
    invoke-virtual {v2, v4, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iget-object v3, v1, Lvp/f;->f:Lvp/b4;

    .line 71
    .line 72
    invoke-virtual {v3}, Lvp/b4;->h()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    invoke-static {v2, v3}, Lvp/t1;->c(Landroid/os/Bundle;Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-boolean v3, v1, Lvp/f;->h:Z

    .line 83
    .line 84
    const-string v4, "active"

    .line 85
    .line 86
    invoke-virtual {v2, v4, v3}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 87
    .line 88
    .line 89
    iget-object v3, v1, Lvp/f;->i:Ljava/lang/String;

    .line 90
    .line 91
    if-eqz v3, :cond_1

    .line 92
    .line 93
    const-string v4, "trigger_event_name"

    .line 94
    .line 95
    invoke-virtual {v2, v4, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    :cond_1
    iget-object v3, v1, Lvp/f;->j:Lvp/t;

    .line 99
    .line 100
    if-eqz v3, :cond_2

    .line 101
    .line 102
    const-string v4, "timed_out_event_name"

    .line 103
    .line 104
    iget-object v5, v3, Lvp/t;->d:Ljava/lang/String;

    .line 105
    .line 106
    invoke-virtual {v2, v4, v5}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    iget-object v3, v3, Lvp/t;->e:Lvp/s;

    .line 110
    .line 111
    if-eqz v3, :cond_2

    .line 112
    .line 113
    const-string v4, "timed_out_event_params"

    .line 114
    .line 115
    invoke-virtual {v3}, Lvp/s;->A0()Landroid/os/Bundle;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    invoke-virtual {v2, v4, v3}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 120
    .line 121
    .line 122
    :cond_2
    iget-wide v3, v1, Lvp/f;->k:J

    .line 123
    .line 124
    const-string v5, "trigger_timeout"

    .line 125
    .line 126
    invoke-virtual {v2, v5, v3, v4}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 127
    .line 128
    .line 129
    iget-object v3, v1, Lvp/f;->l:Lvp/t;

    .line 130
    .line 131
    if-eqz v3, :cond_3

    .line 132
    .line 133
    const-string v4, "triggered_event_name"

    .line 134
    .line 135
    iget-object v5, v3, Lvp/t;->d:Ljava/lang/String;

    .line 136
    .line 137
    invoke-virtual {v2, v4, v5}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    iget-object v3, v3, Lvp/t;->e:Lvp/s;

    .line 141
    .line 142
    if-eqz v3, :cond_3

    .line 143
    .line 144
    const-string v4, "triggered_event_params"

    .line 145
    .line 146
    invoke-virtual {v3}, Lvp/s;->A0()Landroid/os/Bundle;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    invoke-virtual {v2, v4, v3}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 151
    .line 152
    .line 153
    :cond_3
    iget-object v3, v1, Lvp/f;->f:Lvp/b4;

    .line 154
    .line 155
    iget-wide v3, v3, Lvp/b4;->f:J

    .line 156
    .line 157
    const-string v5, "triggered_timestamp"

    .line 158
    .line 159
    invoke-virtual {v2, v5, v3, v4}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 160
    .line 161
    .line 162
    iget-wide v3, v1, Lvp/f;->m:J

    .line 163
    .line 164
    const-string v5, "time_to_live"

    .line 165
    .line 166
    invoke-virtual {v2, v5, v3, v4}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 167
    .line 168
    .line 169
    iget-object v1, v1, Lvp/f;->n:Lvp/t;

    .line 170
    .line 171
    if-eqz v1, :cond_4

    .line 172
    .line 173
    const-string v3, "expired_event_name"

    .line 174
    .line 175
    iget-object v4, v1, Lvp/t;->d:Ljava/lang/String;

    .line 176
    .line 177
    invoke-virtual {v2, v3, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    iget-object v1, v1, Lvp/t;->e:Lvp/s;

    .line 181
    .line 182
    if-eqz v1, :cond_4

    .line 183
    .line 184
    const-string v3, "expired_event_params"

    .line 185
    .line 186
    invoke-virtual {v1}, Lvp/s;->A0()Landroid/os/Bundle;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    invoke-virtual {v2, v3, v1}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 191
    .line 192
    .line 193
    :cond_4
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    goto/16 :goto_0

    .line 197
    .line 198
    :cond_5
    return-object v0
.end method

.method public static Q0(Landroid/content/Context;)Z
    .locals 4

    .line 1
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    new-instance v2, Landroid/content/ComponentName;

    .line 13
    .line 14
    const-string v3, "com.google.android.gms.measurement.AppMeasurementReceiver"

    .line 15
    .line 16
    invoke-direct {v2, p0, v3}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, v2, v0}, Landroid/content/pm/PackageManager;->getReceiverInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ActivityInfo;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    if-eqz p0, :cond_1

    .line 24
    .line 25
    iget-boolean p0, p0, Landroid/content/pm/ActivityInfo;->enabled:Z
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    if-eqz p0, :cond_1

    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :catch_0
    :cond_1
    :goto_0
    return v0
.end method

.method public static R0(Lvp/r2;Landroid/os/Bundle;Z)V
    .locals 4

    .line 1
    const-string v0, "_si"

    .line 2
    .line 3
    const-string v1, "_sn"

    .line 4
    .line 5
    const-string v2, "_sc"

    .line 6
    .line 7
    if-eqz p1, :cond_4

    .line 8
    .line 9
    if-eqz p0, :cond_4

    .line 10
    .line 11
    invoke-virtual {p1, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    if-eqz v3, :cond_1

    .line 16
    .line 17
    if-eqz p2, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p2, 0x0

    .line 21
    goto :goto_3

    .line 22
    :cond_1
    :goto_0
    iget-object p2, p0, Lvp/r2;->a:Ljava/lang/String;

    .line 23
    .line 24
    if-eqz p2, :cond_2

    .line 25
    .line 26
    invoke-virtual {p1, v1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_2
    invoke-virtual {p1, v1}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    :goto_1
    iget-object p2, p0, Lvp/r2;->b:Ljava/lang/String;

    .line 34
    .line 35
    if-eqz p2, :cond_3

    .line 36
    .line 37
    invoke-virtual {p1, v2, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_3
    invoke-virtual {p1, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    :goto_2
    iget-wide v1, p0, Lvp/r2;->c:J

    .line 45
    .line 46
    invoke-virtual {p1, v0, v1, v2}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_4
    :goto_3
    if-eqz p1, :cond_5

    .line 51
    .line 52
    if-nez p0, :cond_5

    .line 53
    .line 54
    if-eqz p2, :cond_5

    .line 55
    .line 56
    invoke-virtual {p1, v1}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    :cond_5
    return-void
.end method

.method public static final T0(ILandroid/os/Bundle;)Z
    .locals 5

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    const-string v0, "_err"

    .line 5
    .line 6
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 7
    .line 8
    .line 9
    move-result-wide v1

    .line 10
    const-wide/16 v3, 0x0

    .line 11
    .line 12
    cmp-long v1, v1, v3

    .line 13
    .line 14
    if-nez v1, :cond_1

    .line 15
    .line 16
    int-to-long v1, p0

    .line 17
    invoke-virtual {p1, v0, v1, v2}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 18
    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public static Y0(Ljava/lang/String;)Z
    .locals 3

    .line 1
    invoke-static {p0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/16 v2, 0x5f

    .line 10
    .line 11
    if-ne v1, v2, :cond_1

    .line 12
    .line 13
    const-string v1, "_ep"

    .line 14
    .line 15
    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return v0

    .line 23
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 24
    return p0
.end method

.method public static f0(Ljava/lang/String;IZ)Ljava/lang/String;
    .locals 2

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-virtual {p0, v1, v0}, Ljava/lang/String;->codePointCount(II)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-le v0, p1, :cond_2

    .line 14
    .line 15
    if-eqz p2, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, v1, p1}, Ljava/lang/String;->offsetByCodePoints(II)I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    invoke-virtual {p0, v1, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string p1, "..."

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 37
    :cond_2
    return-object p0
.end method

.method public static i1(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p0, [Landroid/os/Parcelable;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    instance-of v0, p0, Ljava/util/ArrayList;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    instance-of p0, p0, Landroid/os/Bundle;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public static q0(Lro/f;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;I)V
    .locals 2

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {p2, v0}, Lvp/d4;->T0(ILandroid/os/Bundle;)Z

    .line 7
    .line 8
    .line 9
    invoke-static {p3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    invoke-static {p4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    invoke-virtual {v0, p3, p4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    const/4 p3, 0x6

    .line 25
    if-eq p2, p3, :cond_1

    .line 26
    .line 27
    const/4 p3, 0x7

    .line 28
    if-eq p2, p3, :cond_1

    .line 29
    .line 30
    const/4 p3, 0x2

    .line 31
    if-ne p2, p3, :cond_2

    .line 32
    .line 33
    :cond_1
    int-to-long p2, p5

    .line 34
    const-string p4, "_el"

    .line 35
    .line 36
    invoke-virtual {v0, p4, p2, p3}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 37
    .line 38
    .line 39
    :cond_2
    const-string p2, "_err"

    .line 40
    .line 41
    invoke-virtual {p0, p1, p2, v0}, Lro/f;->r(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public static r0()Ljava/security/MessageDigest;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    const/4 v1, 0x2

    .line 3
    if-ge v0, v1, :cond_1

    .line 4
    .line 5
    :try_start_0
    const-string v1, "MD5"

    .line 6
    .line 7
    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    .line 8
    .line 9
    .line 10
    move-result-object v1
    :try_end_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    goto :goto_1

    .line 14
    :cond_0
    return-object v1

    .line 15
    :catch_0
    :goto_1
    add-int/lit8 v0, v0, 0x1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_1
    const/4 v0, 0x0

    .line 19
    return-object v0
.end method

.method public static s0([B)J
    .locals 8

    .line 1
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    array-length v0, p0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-lez v0, :cond_0

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move v2, v1

    .line 11
    :goto_0
    invoke-static {v2}, Lno/c0;->k(Z)V

    .line 12
    .line 13
    .line 14
    add-int/lit8 v0, v0, -0x1

    .line 15
    .line 16
    const-wide/16 v2, 0x0

    .line 17
    .line 18
    :goto_1
    if-ltz v0, :cond_1

    .line 19
    .line 20
    array-length v4, p0

    .line 21
    add-int/lit8 v4, v4, -0x8

    .line 22
    .line 23
    if-lt v0, v4, :cond_1

    .line 24
    .line 25
    aget-byte v4, p0, v0

    .line 26
    .line 27
    int-to-long v4, v4

    .line 28
    const-wide/16 v6, 0xff

    .line 29
    .line 30
    and-long/2addr v4, v6

    .line 31
    shl-long/2addr v4, v1

    .line 32
    add-long/2addr v2, v4

    .line 33
    add-int/lit8 v1, v1, 0x8

    .line 34
    .line 35
    add-int/lit8 v0, v0, -0x1

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    return-wide v2
.end method

.method public static t0(Landroid/content/Context;)Z
    .locals 4

    .line 1
    const-string v0, "com.google.android.gms.measurement.AppMeasurementJobService"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 5
    .line 6
    .line 7
    move-result-object v2

    .line 8
    if-nez v2, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    new-instance v3, Landroid/content/ComponentName;

    .line 12
    .line 13
    invoke-direct {v3, p0, v0}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v2, v3, v1}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    iget-boolean p0, p0, Landroid/content/pm/ServiceInfo;->enabled:Z
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    return p0

    .line 28
    :catch_0
    :cond_1
    :goto_0
    return v1
.end method

.method public static w0(Ljava/lang/String;)Z
    .locals 2

    .line 1
    sget-object v0, Lvp/z;->r0:Lvp/y;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Ljava/lang/String;

    .line 9
    .line 10
    const-string v1, "*"

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    const-string v1, ","

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-interface {v0, p0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 p0, 0x0

    .line 36
    return p0

    .line 37
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 38
    return p0
.end method

.method public static y0(Ljava/lang/String;)Z
    .locals 1

    .line 1
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, "_"

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public static z0(Ljava/lang/String;[Ljava/lang/String;)Z
    .locals 3

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    move v1, v0

    .line 6
    :goto_0
    array-length v2, p1

    .line 7
    if-ge v1, v2, :cond_1

    .line 8
    .line 9
    aget-object v2, p1, v1

    .line 10
    .line 11
    invoke-static {p0, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    return v0
.end method


# virtual methods
.method public final A0(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 0

    .line 1
    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 10
    .line 11
    .line 12
    move-result p2

    .line 13
    if-eqz p2, :cond_1

    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    return p0

    .line 17
    :cond_1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lvp/g1;

    .line 20
    .line 21
    iget-object p0, p0, Lvp/g1;->g:Lvp/h;

    .line 22
    .line 23
    const-string p2, "debug.firebase.analytics.app"

    .line 24
    .line 25
    invoke-virtual {p0, p2}, Lvp/h;->e0(Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    return p0
.end method

.method public final B0(Landroid/os/Bundle;)Landroid/os/Bundle;
    .locals 5

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    if-eqz p1, :cond_1

    .line 7
    .line 8
    invoke-virtual {p1}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_1

    .line 21
    .line 22
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    check-cast v2, Ljava/lang/String;

    .line 27
    .line 28
    invoke-virtual {p1, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-virtual {p0, v3, v2}, Lvp/d4;->h0(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    if-nez v3, :cond_0

    .line 37
    .line 38
    iget-object v3, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v3, Lvp/g1;

    .line 41
    .line 42
    iget-object v4, v3, Lvp/g1;->i:Lvp/p0;

    .line 43
    .line 44
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 45
    .line 46
    .line 47
    iget-object v4, v4, Lvp/p0;->o:Lvp/n0;

    .line 48
    .line 49
    iget-object v3, v3, Lvp/g1;->m:Lvp/k0;

    .line 50
    .line 51
    invoke-virtual {v3, v2}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    const-string v3, "Param value can\'t be null"

    .line 56
    .line 57
    invoke-virtual {v4, v2, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    invoke-virtual {p0, v0, v2, v3}, Lvp/d4;->p0(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    return-object v0
.end method

.method public final C0(Ljava/lang/String;Landroid/os/Bundle;Ljava/lang/String;JZ)Lvp/t;
    .locals 6

    .line 1
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

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
    invoke-virtual {p0, p1}, Lvp/d4;->e1(Ljava/lang/String;)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_3

    .line 14
    .line 15
    if-eqz p2, :cond_1

    .line 16
    .line 17
    new-instance v0, Landroid/os/Bundle;

    .line 18
    .line 19
    invoke-direct {v0, p2}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    new-instance v0, Landroid/os/Bundle;

    .line 24
    .line 25
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 26
    .line 27
    .line 28
    :goto_0
    const-string p2, "_o"

    .line 29
    .line 30
    invoke-virtual {v0, p2, p3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {p2}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    const/4 v1, 0x1

    .line 38
    invoke-virtual {p0, p1, v0, p2, v1}, Lvp/d4;->i0(Ljava/lang/String;Landroid/os/Bundle;Ljava/util/List;Z)Landroid/os/Bundle;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    if-eqz p6, :cond_2

    .line 43
    .line 44
    invoke-virtual {p0, p2}, Lvp/d4;->B0(Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    :cond_2
    invoke-static {p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance v0, Lvp/t;

    .line 52
    .line 53
    new-instance v2, Lvp/s;

    .line 54
    .line 55
    invoke-direct {v2, p2}, Lvp/s;-><init>(Landroid/os/Bundle;)V

    .line 56
    .line 57
    .line 58
    move-object v1, p1

    .line 59
    move-object v3, p3

    .line 60
    move-wide v4, p4

    .line 61
    invoke-direct/range {v0 .. v5}, Lvp/t;-><init>(Ljava/lang/String;Lvp/s;Ljava/lang/String;J)V

    .line 62
    .line 63
    .line 64
    return-object v0

    .line 65
    :cond_3
    move-object v1, p1

    .line 66
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Lvp/g1;

    .line 69
    .line 70
    iget-object p1, p0, Lvp/g1;->i:Lvp/p0;

    .line 71
    .line 72
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 73
    .line 74
    .line 75
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 76
    .line 77
    iget-object p0, p0, Lvp/g1;->m:Lvp/k0;

    .line 78
    .line 79
    invoke-virtual {p0, v1}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    const-string p2, "Invalid conditional property event name"

    .line 84
    .line 85
    invoke-virtual {p1, p0, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 89
    .line 90
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 91
    .line 92
    .line 93
    throw p0
.end method

.method public final D0(Landroid/content/Context;Ljava/lang/String;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    new-instance v0, Ljavax/security/auth/x500/X500Principal;

    .line 6
    .line 7
    const-string v1, "CN=Android Debug,O=Android,C=US"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljavax/security/auth/x500/X500Principal;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :try_start_0
    invoke-static {p1}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const/16 v1, 0x40

    .line 17
    .line 18
    invoke-virtual {p1, v1, p2}, Lcq/r1;->c(ILjava/lang/String;)Landroid/content/pm/PackageInfo;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    iget-object p1, p1, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 25
    .line 26
    if-eqz p1, :cond_0

    .line 27
    .line 28
    array-length p2, p1

    .line 29
    if-lez p2, :cond_0

    .line 30
    .line 31
    const/4 p2, 0x0

    .line 32
    aget-object p1, p1, p2

    .line 33
    .line 34
    const-string p2, "X.509"

    .line 35
    .line 36
    invoke-static {p2}, Ljava/security/cert/CertificateFactory;->getInstance(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    new-instance v1, Ljava/io/ByteArrayInputStream;

    .line 41
    .line 42
    invoke-virtual {p1}, Landroid/content/pm/Signature;->toByteArray()[B

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-direct {v1, p1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2, v1}, Ljava/security/cert/CertificateFactory;->generateCertificate(Ljava/io/InputStream;)Ljava/security/cert/Certificate;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    check-cast p1, Ljava/security/cert/X509Certificate;

    .line 54
    .line 55
    invoke-virtual {p1}, Ljava/security/cert/X509Certificate;->getSubjectX500Principal()Ljavax/security/auth/x500/X500Principal;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-virtual {p1, v0}, Ljavax/security/auth/x500/X500Principal;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result p0
    :try_end_0
    .catch Ljava/security/cert/CertificateException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 63
    return p0

    .line 64
    :catch_0
    move-exception p1

    .line 65
    goto :goto_0

    .line 66
    :catch_1
    move-exception p1

    .line 67
    goto :goto_1

    .line 68
    :goto_0
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 69
    .line 70
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 74
    .line 75
    const-string p2, "Package name not found"

    .line 76
    .line 77
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    goto :goto_2

    .line 81
    :goto_1
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 82
    .line 83
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 84
    .line 85
    .line 86
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 87
    .line 88
    const-string p2, "Error obtaining certificate"

    .line 89
    .line 90
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    :cond_0
    :goto_2
    const/4 p0, 0x1

    .line 94
    return p0
.end method

.method public final F0(I)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    invoke-virtual {v0}, Lvp/g1;->o()Lvp/d3;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v0, v0, Lvp/d3;->i:Ljava/lang/Boolean;

    .line 10
    .line 11
    invoke-virtual {p0}, Lvp/d4;->G0()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    div-int/lit16 p1, p1, 0x3e8

    .line 16
    .line 17
    if-ge p0, p1, :cond_1

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-nez p0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    return p0

    .line 30
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 31
    return p0
.end method

.method public final G0()I
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/d4;->l:Ljava/lang/Integer;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lvp/g1;

    .line 8
    .line 9
    sget-object v1, Ljo/f;->b:Ljo/f;

    .line 10
    .line 11
    iget-object v0, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    invoke-static {v0}, Ljo/f;->a(Landroid/content/Context;)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    div-int/lit16 v0, v0, 0x3e8

    .line 21
    .line 22
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    iput-object v0, p0, Lvp/d4;->l:Ljava/lang/Integer;

    .line 27
    .line 28
    :cond_0
    iget-object p0, p0, Lvp/d4;->l:Ljava/lang/Integer;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    return p0
.end method

.method public final H0(Landroid/os/Bundle;J)V
    .locals 6

    .line 1
    const-string v0, "_et"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    const-wide/16 v3, 0x0

    .line 8
    .line 9
    cmp-long v5, v1, v3

    .line 10
    .line 11
    if-eqz v5, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lvp/g1;

    .line 16
    .line 17
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 18
    .line 19
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 23
    .line 24
    const-string v3, "Params already contained engagement"

    .line 25
    .line 26
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    invoke-virtual {p0, v4, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move-wide v1, v3

    .line 35
    :goto_0
    add-long/2addr p2, v1

    .line 36
    invoke-virtual {p1, v0, p2, p3}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public final I0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V
    .locals 2

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "r"

    .line 7
    .line 8
    invoke-virtual {v0, v1, p1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    invoke-interface {p2, v0}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception p1

    .line 16
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lvp/g1;

    .line 19
    .line 20
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 21
    .line 22
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 26
    .line 27
    const-string p2, "Error returning string value to wrapper"

    .line 28
    .line 29
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final J0(Lcom/google/android/gms/internal/measurement/m0;J)V
    .locals 2

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "r"

    .line 7
    .line 8
    invoke-virtual {v0, v1, p2, p3}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    invoke-interface {p1, v0}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception p1

    .line 16
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lvp/g1;

    .line 19
    .line 20
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 21
    .line 22
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 26
    .line 27
    const-string p2, "Error returning long value to wrapper"

    .line 28
    .line 29
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final K0(Lcom/google/android/gms/internal/measurement/m0;I)V
    .locals 2

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "r"

    .line 7
    .line 8
    invoke-virtual {v0, v1, p2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    invoke-interface {p1, v0}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception p1

    .line 16
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lvp/g1;

    .line 19
    .line 20
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 21
    .line 22
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 26
    .line 27
    const-string p2, "Error returning int value to wrapper"

    .line 28
    .line 29
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final L0(Lcom/google/android/gms/internal/measurement/m0;[B)V
    .locals 2

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "r"

    .line 7
    .line 8
    invoke-virtual {v0, v1, p2}, Landroid/os/Bundle;->putByteArray(Ljava/lang/String;[B)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    invoke-interface {p1, v0}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception p1

    .line 16
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lvp/g1;

    .line 19
    .line 20
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 21
    .line 22
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 26
    .line 27
    const-string p2, "Error returning byte array to wrapper"

    .line 28
    .line 29
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final M0(Lcom/google/android/gms/internal/measurement/m0;Z)V
    .locals 2

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "r"

    .line 7
    .line 8
    invoke-virtual {v0, v1, p2}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    invoke-interface {p1, v0}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception p1

    .line 16
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lvp/g1;

    .line 19
    .line 20
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 21
    .line 22
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 26
    .line 27
    const-string p2, "Error returning boolean value to wrapper"

    .line 28
    .line 29
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final N0(Lcom/google/android/gms/internal/measurement/m0;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    :try_start_0
    invoke-interface {p1, p2}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 2
    .line 3
    .line 4
    return-void

    .line 5
    :catch_0
    move-exception p1

    .line 6
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lvp/g1;

    .line 9
    .line 10
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 11
    .line 12
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 16
    .line 17
    const-string p2, "Error returning bundle value to wrapper"

    .line 18
    .line 19
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final O0(Lcom/google/android/gms/internal/measurement/m0;Ljava/util/ArrayList;)V
    .locals 2

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "r"

    .line 7
    .line 8
    invoke-virtual {v0, v1, p2}, Landroid/os/Bundle;->putParcelableArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    invoke-interface {p1, v0}, Lcom/google/android/gms/internal/measurement/m0;->I(Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception p1

    .line 16
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lvp/g1;

    .line 19
    .line 20
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 21
    .line 22
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 26
    .line 27
    const-string p2, "Error returning bundle list to wrapper"

    .line 28
    .line 29
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final S0()Ljava/lang/String;
    .locals 3

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    invoke-virtual {p0}, Lvp/d4;->X0()Ljava/security/SecureRandom;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0, v0}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 10
    .line 11
    .line 12
    sget-object p0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 13
    .line 14
    new-instance v1, Ljava/math/BigInteger;

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    invoke-direct {v1, v2, v0}, Ljava/math/BigInteger;-><init>(I[B)V

    .line 18
    .line 19
    .line 20
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v1, "%032x"

    .line 25
    .line 26
    invoke-static {p0, v1, v0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public final U0(ILjava/lang/Object;ZZ)Ljava/lang/Object;
    .locals 2

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    goto/16 :goto_2

    .line 4
    .line 5
    :cond_0
    instance-of v0, p2, Ljava/lang/Long;

    .line 6
    .line 7
    if-nez v0, :cond_e

    .line 8
    .line 9
    instance-of v0, p2, Ljava/lang/Double;

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    return-object p2

    .line 14
    :cond_1
    instance-of v0, p2, Ljava/lang/Integer;

    .line 15
    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    check-cast p2, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    int-to-long p0, p0

    .line 25
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_2
    instance-of v0, p2, Ljava/lang/Byte;

    .line 31
    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    check-cast p2, Ljava/lang/Byte;

    .line 35
    .line 36
    invoke-virtual {p2}, Ljava/lang/Byte;->byteValue()B

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    int-to-long p0, p0

    .line 41
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0

    .line 46
    :cond_3
    instance-of v0, p2, Ljava/lang/Short;

    .line 47
    .line 48
    if-eqz v0, :cond_4

    .line 49
    .line 50
    check-cast p2, Ljava/lang/Short;

    .line 51
    .line 52
    invoke-virtual {p2}, Ljava/lang/Short;->shortValue()S

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    int-to-long p0, p0

    .line 57
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :cond_4
    instance-of v0, p2, Ljava/lang/Boolean;

    .line 63
    .line 64
    if-eqz v0, :cond_6

    .line 65
    .line 66
    check-cast p2, Ljava/lang/Boolean;

    .line 67
    .line 68
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    const/4 p1, 0x1

    .line 73
    if-eq p1, p0, :cond_5

    .line 74
    .line 75
    const-wide/16 p0, 0x0

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_5
    const-wide/16 p0, 0x1

    .line 79
    .line 80
    :goto_0
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :cond_6
    instance-of v0, p2, Ljava/lang/Float;

    .line 86
    .line 87
    if-eqz v0, :cond_7

    .line 88
    .line 89
    check-cast p2, Ljava/lang/Float;

    .line 90
    .line 91
    invoke-virtual {p2}, Ljava/lang/Float;->doubleValue()D

    .line 92
    .line 93
    .line 94
    move-result-wide p0

    .line 95
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0

    .line 100
    :cond_7
    instance-of v0, p2, Ljava/lang/String;

    .line 101
    .line 102
    if-nez v0, :cond_d

    .line 103
    .line 104
    instance-of v0, p2, Ljava/lang/Character;

    .line 105
    .line 106
    if-nez v0, :cond_d

    .line 107
    .line 108
    instance-of v0, p2, Ljava/lang/CharSequence;

    .line 109
    .line 110
    if-eqz v0, :cond_8

    .line 111
    .line 112
    goto :goto_3

    .line 113
    :cond_8
    if-eqz p4, :cond_c

    .line 114
    .line 115
    instance-of p1, p2, [Landroid/os/Bundle;

    .line 116
    .line 117
    if-nez p1, :cond_9

    .line 118
    .line 119
    instance-of p1, p2, [Landroid/os/Parcelable;

    .line 120
    .line 121
    if-eqz p1, :cond_c

    .line 122
    .line 123
    :cond_9
    new-instance p1, Ljava/util/ArrayList;

    .line 124
    .line 125
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 126
    .line 127
    .line 128
    check-cast p2, [Landroid/os/Parcelable;

    .line 129
    .line 130
    array-length p3, p2

    .line 131
    const/4 p4, 0x0

    .line 132
    :goto_1
    if-ge p4, p3, :cond_b

    .line 133
    .line 134
    aget-object v0, p2, p4

    .line 135
    .line 136
    instance-of v1, v0, Landroid/os/Bundle;

    .line 137
    .line 138
    if-eqz v1, :cond_a

    .line 139
    .line 140
    check-cast v0, Landroid/os/Bundle;

    .line 141
    .line 142
    invoke-virtual {p0, v0}, Lvp/d4;->B0(Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    invoke-virtual {v0}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    if-nez v1, :cond_a

    .line 151
    .line 152
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    :cond_a
    add-int/lit8 p4, p4, 0x1

    .line 156
    .line 157
    goto :goto_1

    .line 158
    :cond_b
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 159
    .line 160
    .line 161
    move-result p0

    .line 162
    new-array p0, p0, [Landroid/os/Bundle;

    .line 163
    .line 164
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    return-object p0

    .line 169
    :cond_c
    :goto_2
    const/4 p0, 0x0

    .line 170
    return-object p0

    .line 171
    :cond_d
    :goto_3
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    invoke-static {p0, p1, p3}, Lvp/d4;->f0(Ljava/lang/String;IZ)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    return-object p0

    .line 180
    :cond_e
    return-object p2
.end method

.method public final V0(Ljava/lang/String;)I
    .locals 1

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    const-string v0, "_ldl"

    .line 6
    .line 7
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const/16 p0, 0x800

    .line 17
    .line 18
    return p0

    .line 19
    :cond_0
    const-string v0, "_id"

    .line 20
    .line 21
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    const/16 p0, 0x100

    .line 31
    .line 32
    return p0

    .line 33
    :cond_1
    const-string v0, "_lgclid"

    .line 34
    .line 35
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_2

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    const/16 p0, 0x64

    .line 45
    .line 46
    return p0

    .line 47
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    const/16 p0, 0x24

    .line 51
    .line 52
    return p0
.end method

.method public final W0()J
    .locals 6

    .line 1
    iget-object v0, p0, Lvp/d4;->h:Ljava/util/concurrent/atomic/AtomicLong;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    const-wide/16 v3, 0x0

    .line 8
    .line 9
    cmp-long v1, v1, v3

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    monitor-enter v0

    .line 14
    :try_start_0
    new-instance v1, Ljava/util/Random;

    .line 15
    .line 16
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 17
    .line 18
    .line 19
    move-result-wide v2

    .line 20
    iget-object v4, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v4, Lvp/g1;

    .line 23
    .line 24
    iget-object v4, v4, Lvp/g1;->n:Lto/a;

    .line 25
    .line 26
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 30
    .line 31
    .line 32
    move-result-wide v4

    .line 33
    xor-long/2addr v2, v4

    .line 34
    invoke-direct {v1, v2, v3}, Ljava/util/Random;-><init>(J)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/util/Random;->nextLong()J

    .line 38
    .line 39
    .line 40
    move-result-wide v1

    .line 41
    iget v3, p0, Lvp/d4;->i:I

    .line 42
    .line 43
    add-int/lit8 v3, v3, 0x1

    .line 44
    .line 45
    iput v3, p0, Lvp/d4;->i:I

    .line 46
    .line 47
    int-to-long v3, v3

    .line 48
    add-long/2addr v1, v3

    .line 49
    monitor-exit v0

    .line 50
    return-wide v1

    .line 51
    :catchall_0
    move-exception p0

    .line 52
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    throw p0

    .line 54
    :cond_0
    iget-object p0, p0, Lvp/d4;->h:Ljava/util/concurrent/atomic/AtomicLong;

    .line 55
    .line 56
    monitor-enter p0

    .line 57
    const-wide/16 v0, -0x1

    .line 58
    .line 59
    const-wide/16 v2, 0x1

    .line 60
    .line 61
    :try_start_1
    invoke-virtual {p0, v0, v1, v2, v3}, Ljava/util/concurrent/atomic/AtomicLong;->compareAndSet(JJ)Z

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicLong;->getAndIncrement()J

    .line 65
    .line 66
    .line 67
    move-result-wide v0

    .line 68
    monitor-exit p0

    .line 69
    return-wide v0

    .line 70
    :catchall_1
    move-exception v0

    .line 71
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 72
    throw v0
.end method

.method public final X0()Ljava/security/SecureRandom;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lvp/d4;->g:Ljava/security/SecureRandom;

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    new-instance v0, Ljava/security/SecureRandom;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/security/SecureRandom;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lvp/d4;->g:Ljava/security/SecureRandom;

    .line 14
    .line 15
    :cond_0
    iget-object p0, p0, Lvp/d4;->g:Ljava/security/SecureRandom;

    .line 16
    .line 17
    return-object p0
.end method

.method public final Z0(Landroid/net/Uri;)Landroid/os/Bundle;
    .locals 17

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_17

    .line 5
    .line 6
    :try_start_0
    invoke-virtual {v0}, Landroid/net/Uri;->isHierarchical()Z

    .line 7
    .line 8
    .line 9
    move-result v2
    :try_end_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    const-string v3, "sfmc_id"

    .line 11
    .line 12
    const-string v4, "srsltid"

    .line 13
    .line 14
    const-string v5, "dclid"

    .line 15
    .line 16
    const-string v6, "gbraid"

    .line 17
    .line 18
    const-string v7, "gclid"

    .line 19
    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    :try_start_1
    const-string v2, "utm_campaign"

    .line 23
    .line 24
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    const-string v8, "utm_source"

    .line 29
    .line 30
    invoke-virtual {v0, v8}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v8

    .line 34
    const-string v9, "utm_medium"

    .line 35
    .line 36
    invoke-virtual {v0, v9}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v9

    .line 40
    invoke-virtual {v0, v7}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v10

    .line 44
    invoke-virtual {v0, v6}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v11

    .line 48
    const-string v12, "utm_id"

    .line 49
    .line 50
    invoke-virtual {v0, v12}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v12

    .line 54
    invoke-virtual {v0, v5}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v13

    .line 58
    invoke-virtual {v0, v4}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v14

    .line 62
    invoke-virtual {v0, v3}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v15
    :try_end_1
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 66
    goto :goto_0

    .line 67
    :catch_0
    move-exception v0

    .line 68
    move-object/from16 v2, p0

    .line 69
    .line 70
    goto/16 :goto_4

    .line 71
    .line 72
    :cond_0
    move-object v2, v1

    .line 73
    move-object v8, v2

    .line 74
    move-object v9, v8

    .line 75
    move-object v10, v9

    .line 76
    move-object v11, v10

    .line 77
    move-object v12, v11

    .line 78
    move-object v13, v12

    .line 79
    move-object v14, v13

    .line 80
    move-object v15, v14

    .line 81
    :goto_0
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 82
    .line 83
    .line 84
    move-result v16

    .line 85
    if-eqz v16, :cond_2

    .line 86
    .line 87
    invoke-static {v8}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 88
    .line 89
    .line 90
    move-result v16

    .line 91
    if-eqz v16, :cond_2

    .line 92
    .line 93
    invoke-static {v9}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 94
    .line 95
    .line 96
    move-result v16

    .line 97
    if-eqz v16, :cond_2

    .line 98
    .line 99
    invoke-static {v10}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 100
    .line 101
    .line 102
    move-result v16

    .line 103
    if-eqz v16, :cond_2

    .line 104
    .line 105
    invoke-static {v11}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 106
    .line 107
    .line 108
    move-result v16

    .line 109
    if-eqz v16, :cond_2

    .line 110
    .line 111
    invoke-static {v12}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 112
    .line 113
    .line 114
    move-result v16

    .line 115
    if-eqz v16, :cond_2

    .line 116
    .line 117
    invoke-static {v13}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 118
    .line 119
    .line 120
    move-result v16

    .line 121
    if-eqz v16, :cond_2

    .line 122
    .line 123
    invoke-static {v14}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 124
    .line 125
    .line 126
    move-result v16

    .line 127
    if-eqz v16, :cond_2

    .line 128
    .line 129
    invoke-static {v15}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 130
    .line 131
    .line 132
    move-result v16

    .line 133
    if-nez v16, :cond_1

    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_1
    return-object v1

    .line 137
    :cond_2
    :goto_1
    new-instance v1, Landroid/os/Bundle;

    .line 138
    .line 139
    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    .line 140
    .line 141
    .line 142
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 143
    .line 144
    .line 145
    move-result v16

    .line 146
    if-nez v16, :cond_3

    .line 147
    .line 148
    move-object/from16 v16, v3

    .line 149
    .line 150
    const-string v3, "campaign"

    .line 151
    .line 152
    invoke-virtual {v1, v3, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_3
    move-object/from16 v16, v3

    .line 157
    .line 158
    :goto_2
    invoke-static {v8}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 159
    .line 160
    .line 161
    move-result v2

    .line 162
    if-nez v2, :cond_4

    .line 163
    .line 164
    const-string v2, "source"

    .line 165
    .line 166
    invoke-virtual {v1, v2, v8}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    :cond_4
    invoke-static {v9}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 170
    .line 171
    .line 172
    move-result v2

    .line 173
    if-nez v2, :cond_5

    .line 174
    .line 175
    const-string v2, "medium"

    .line 176
    .line 177
    invoke-virtual {v1, v2, v9}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    :cond_5
    invoke-static {v10}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 181
    .line 182
    .line 183
    move-result v2

    .line 184
    if-nez v2, :cond_6

    .line 185
    .line 186
    invoke-virtual {v1, v7, v10}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    :cond_6
    invoke-static {v11}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 190
    .line 191
    .line 192
    move-result v2

    .line 193
    if-nez v2, :cond_7

    .line 194
    .line 195
    invoke-virtual {v1, v6, v11}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    :cond_7
    const-string v2, "gad_source"

    .line 199
    .line 200
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v3

    .line 204
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 205
    .line 206
    .line 207
    move-result v6

    .line 208
    if-nez v6, :cond_8

    .line 209
    .line 210
    invoke-virtual {v1, v2, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    :cond_8
    const-string v2, "utm_term"

    .line 214
    .line 215
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v2

    .line 219
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 220
    .line 221
    .line 222
    move-result v3

    .line 223
    if-nez v3, :cond_9

    .line 224
    .line 225
    const-string v3, "term"

    .line 226
    .line 227
    invoke-virtual {v1, v3, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    :cond_9
    const-string v2, "utm_content"

    .line 231
    .line 232
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object v2

    .line 236
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 237
    .line 238
    .line 239
    move-result v3

    .line 240
    if-nez v3, :cond_a

    .line 241
    .line 242
    const-string v3, "content"

    .line 243
    .line 244
    invoke-virtual {v1, v3, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    :cond_a
    const-string v2, "aclid"

    .line 248
    .line 249
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 250
    .line 251
    .line 252
    move-result-object v3

    .line 253
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 254
    .line 255
    .line 256
    move-result v6

    .line 257
    if-nez v6, :cond_b

    .line 258
    .line 259
    invoke-virtual {v1, v2, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 260
    .line 261
    .line 262
    :cond_b
    const-string v2, "cp1"

    .line 263
    .line 264
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object v3

    .line 268
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 269
    .line 270
    .line 271
    move-result v6

    .line 272
    if-nez v6, :cond_c

    .line 273
    .line 274
    invoke-virtual {v1, v2, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 275
    .line 276
    .line 277
    :cond_c
    const-string v2, "anid"

    .line 278
    .line 279
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object v3

    .line 283
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 284
    .line 285
    .line 286
    move-result v6

    .line 287
    if-nez v6, :cond_d

    .line 288
    .line 289
    invoke-virtual {v1, v2, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    :cond_d
    invoke-static {v12}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 293
    .line 294
    .line 295
    move-result v2

    .line 296
    if-nez v2, :cond_e

    .line 297
    .line 298
    const-string v2, "campaign_id"

    .line 299
    .line 300
    invoke-virtual {v1, v2, v12}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    :cond_e
    invoke-static {v13}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 304
    .line 305
    .line 306
    move-result v2

    .line 307
    if-nez v2, :cond_f

    .line 308
    .line 309
    invoke-virtual {v1, v5, v13}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    :cond_f
    const-string v2, "utm_source_platform"

    .line 313
    .line 314
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object v2

    .line 318
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 319
    .line 320
    .line 321
    move-result v3

    .line 322
    if-nez v3, :cond_10

    .line 323
    .line 324
    const-string v3, "source_platform"

    .line 325
    .line 326
    invoke-virtual {v1, v3, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    :cond_10
    const-string v2, "utm_creative_format"

    .line 330
    .line 331
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 332
    .line 333
    .line 334
    move-result-object v2

    .line 335
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 336
    .line 337
    .line 338
    move-result v3

    .line 339
    if-nez v3, :cond_11

    .line 340
    .line 341
    const-string v3, "creative_format"

    .line 342
    .line 343
    invoke-virtual {v1, v3, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    :cond_11
    const-string v2, "utm_marketing_tactic"

    .line 347
    .line 348
    invoke-virtual {v0, v2}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 349
    .line 350
    .line 351
    move-result-object v2

    .line 352
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 353
    .line 354
    .line 355
    move-result v3

    .line 356
    if-nez v3, :cond_12

    .line 357
    .line 358
    const-string v3, "marketing_tactic"

    .line 359
    .line 360
    invoke-virtual {v1, v3, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 361
    .line 362
    .line 363
    :cond_12
    invoke-static {v14}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 364
    .line 365
    .line 366
    move-result v2

    .line 367
    if-nez v2, :cond_13

    .line 368
    .line 369
    invoke-virtual {v1, v4, v14}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 370
    .line 371
    .line 372
    :cond_13
    invoke-static {v15}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 373
    .line 374
    .line 375
    move-result v2

    .line 376
    if-nez v2, :cond_14

    .line 377
    .line 378
    move-object/from16 v2, v16

    .line 379
    .line 380
    invoke-virtual {v1, v2, v15}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 381
    .line 382
    .line 383
    :cond_14
    invoke-virtual {v0}, Landroid/net/Uri;->getQueryParameterNames()Ljava/util/Set;

    .line 384
    .line 385
    .line 386
    move-result-object v2

    .line 387
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 388
    .line 389
    .line 390
    move-result-object v2

    .line 391
    :cond_15
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 392
    .line 393
    .line 394
    move-result v3

    .line 395
    if-eqz v3, :cond_16

    .line 396
    .line 397
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    move-result-object v3

    .line 401
    check-cast v3, Ljava/lang/String;

    .line 402
    .line 403
    const-string v4, "gad_"

    .line 404
    .line 405
    invoke-virtual {v3, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 406
    .line 407
    .line 408
    move-result v4

    .line 409
    if-eqz v4, :cond_15

    .line 410
    .line 411
    invoke-virtual {v0, v3}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;

    .line 412
    .line 413
    .line 414
    move-result-object v4

    .line 415
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 416
    .line 417
    .line 418
    move-result v5

    .line 419
    if-nez v5, :cond_15

    .line 420
    .line 421
    invoke-virtual {v1, v3, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 422
    .line 423
    .line 424
    goto :goto_3

    .line 425
    :cond_16
    return-object v1

    .line 426
    :goto_4
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 427
    .line 428
    check-cast v2, Lvp/g1;

    .line 429
    .line 430
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 431
    .line 432
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 433
    .line 434
    .line 435
    iget-object v2, v2, Lvp/p0;->m:Lvp/n0;

    .line 436
    .line 437
    const-string v3, "Install referrer url isn\'t a hierarchical URI"

    .line 438
    .line 439
    invoke-virtual {v2, v0, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 440
    .line 441
    .line 442
    :cond_17
    return-object v1
.end method

.method public final a1(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 5

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-nez p2, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 9
    .line 10
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 14
    .line 15
    const-string p2, "Name is required and can\'t be null. Type"

    .line 16
    .line 17
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return v0

    .line 21
    :cond_0
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 28
    .line 29
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 33
    .line 34
    const-string p2, "Name is required and can\'t be empty. Type"

    .line 35
    .line 36
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return v0

    .line 40
    :cond_1
    invoke-virtual {p2, v0}, Ljava/lang/String;->codePointAt(I)I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    invoke-static {v1}, Ljava/lang/Character;->isLetter(I)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-nez v2, :cond_2

    .line 49
    .line 50
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 51
    .line 52
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 56
    .line 57
    const-string v1, "Name must start with a letter. Type, name"

    .line 58
    .line 59
    invoke-virtual {p0, p1, p2, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    return v0

    .line 63
    :cond_2
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    invoke-static {v1}, Ljava/lang/Character;->charCount(I)I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    :goto_0
    if-ge v1, v2, :cond_5

    .line 72
    .line 73
    invoke-virtual {p2, v1}, Ljava/lang/String;->codePointAt(I)I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    const/16 v4, 0x5f

    .line 78
    .line 79
    if-eq v3, v4, :cond_4

    .line 80
    .line 81
    invoke-static {v3}, Ljava/lang/Character;->isLetterOrDigit(I)Z

    .line 82
    .line 83
    .line 84
    move-result v4

    .line 85
    if-eqz v4, :cond_3

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_3
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 89
    .line 90
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 91
    .line 92
    .line 93
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 94
    .line 95
    const-string v1, "Name must consist of letters, digits or _ (underscores). Type, name"

    .line 96
    .line 97
    invoke-virtual {p0, p1, p2, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    return v0

    .line 101
    :cond_4
    :goto_1
    invoke-static {v3}, Ljava/lang/Character;->charCount(I)I

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    add-int/2addr v1, v3

    .line 106
    goto :goto_0

    .line 107
    :cond_5
    const/4 p0, 0x1

    .line 108
    return p0
.end method

.method public final b0()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final b1(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 6

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-nez p2, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 9
    .line 10
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 14
    .line 15
    const-string p2, "Name is required and can\'t be null. Type"

    .line 16
    .line 17
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return v0

    .line 21
    :cond_0
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 28
    .line 29
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 33
    .line 34
    const-string p2, "Name is required and can\'t be empty. Type"

    .line 35
    .line 36
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return v0

    .line 40
    :cond_1
    invoke-virtual {p2, v0}, Ljava/lang/String;->codePointAt(I)I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    invoke-static {v1}, Ljava/lang/Character;->isLetter(I)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    const/16 v3, 0x5f

    .line 49
    .line 50
    if-nez v2, :cond_3

    .line 51
    .line 52
    if-ne v1, v3, :cond_2

    .line 53
    .line 54
    move v1, v3

    .line 55
    goto :goto_0

    .line 56
    :cond_2
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 57
    .line 58
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 59
    .line 60
    .line 61
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 62
    .line 63
    const-string v1, "Name must start with a letter or _ (underscore). Type, name"

    .line 64
    .line 65
    invoke-virtual {p0, p1, p2, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    return v0

    .line 69
    :cond_3
    :goto_0
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    invoke-static {v1}, Ljava/lang/Character;->charCount(I)I

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    :goto_1
    if-ge v1, v2, :cond_6

    .line 78
    .line 79
    invoke-virtual {p2, v1}, Ljava/lang/String;->codePointAt(I)I

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    if-eq v4, v3, :cond_5

    .line 84
    .line 85
    invoke-static {v4}, Ljava/lang/Character;->isLetterOrDigit(I)Z

    .line 86
    .line 87
    .line 88
    move-result v5

    .line 89
    if-eqz v5, :cond_4

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_4
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 93
    .line 94
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 95
    .line 96
    .line 97
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 98
    .line 99
    const-string v1, "Name must consist of letters, digits or _ (underscores). Type, name"

    .line 100
    .line 101
    invoke-virtual {p0, p1, p2, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    return v0

    .line 105
    :cond_5
    :goto_2
    invoke-static {v4}, Ljava/lang/Character;->charCount(I)I

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    add-int/2addr v1, v4

    .line 110
    goto :goto_1

    .line 111
    :cond_6
    const/4 p0, 0x1

    .line 112
    return p0
.end method

.method public final c1(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z
    .locals 3

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-nez p3, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 9
    .line 10
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 14
    .line 15
    const-string p2, "Name is required and can\'t be null. Type"

    .line 16
    .line 17
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return v0

    .line 21
    :cond_0
    move v1, v0

    .line 22
    :goto_0
    const/4 v2, 0x3

    .line 23
    if-ge v1, v2, :cond_2

    .line 24
    .line 25
    sget-object v2, Lvp/d4;->m:[Ljava/lang/String;

    .line 26
    .line 27
    aget-object v2, v2, v1

    .line 28
    .line 29
    invoke-virtual {p3, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 36
    .line 37
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 41
    .line 42
    const-string p2, "Name starts with reserved prefix. Type, name"

    .line 43
    .line 44
    invoke-virtual {p0, p1, p3, p2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    return v0

    .line 48
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    if-eqz p2, :cond_4

    .line 52
    .line 53
    invoke-static {p3, p2}, Lvp/d4;->z0(Ljava/lang/String;[Ljava/lang/String;)Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-eqz p2, :cond_4

    .line 58
    .line 59
    if-eqz p4, :cond_3

    .line 60
    .line 61
    invoke-static {p3, p4}, Lvp/d4;->z0(Ljava/lang/String;[Ljava/lang/String;)Z

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    if-nez p2, :cond_4

    .line 66
    .line 67
    :cond_3
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 68
    .line 69
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 70
    .line 71
    .line 72
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 73
    .line 74
    const-string p2, "Name is reserved. Type, name"

    .line 75
    .line 76
    invoke-virtual {p0, p1, p3, p2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    return v0

    .line 80
    :cond_4
    const/4 p0, 0x1

    .line 81
    return p0
.end method

.method public final d1(Ljava/lang/String;ILjava/lang/String;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-nez p3, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 9
    .line 10
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 14
    .line 15
    const-string p2, "Name is required and can\'t be null. Type"

    .line 16
    .line 17
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return v0

    .line 21
    :cond_0
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    invoke-virtual {p3, v0, v1}, Ljava/lang/String;->codePointCount(II)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-le v1, p2, :cond_1

    .line 30
    .line 31
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 32
    .line 33
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 37
    .line 38
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    const-string v1, "Name is too long. Type, maximum supported length, name"

    .line 43
    .line 44
    invoke-virtual {p0, v1, p1, p2, p3}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return v0

    .line 48
    :cond_1
    const/4 p0, 0x1

    .line 49
    return p0
.end method

.method public final e0(Ljava/lang/String;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "^1:\\d+:android:[a-f0-9]+$"

    .line 16
    .line 17
    invoke-virtual {p1, v0}, Ljava/lang/String;->matches(Ljava/lang/String;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 24
    .line 25
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 29
    .line 30
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    const-string v0, "Invalid google_app_id. Firebase Analytics disabled. See https://goo.gl/NAOOOI. provided id"

    .line 35
    .line 36
    invoke-virtual {p0, p1, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return v1

    .line 40
    :cond_0
    const/4 p0, 0x1

    .line 41
    return p0

    .line 42
    :cond_1
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 43
    .line 44
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 48
    .line 49
    const-string p1, "Missing google_app_id. Firebase Analytics disabled. See https://goo.gl/NAOOOI"

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    return v1
.end method

.method public final e1(Ljava/lang/String;)I
    .locals 4

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-virtual {p0, v0, p1}, Lvp/d4;->b1(Ljava/lang/String;Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x2

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    return v2

    .line 11
    :cond_0
    sget-object v1, Lvp/t1;->a:[Ljava/lang/String;

    .line 12
    .line 13
    sget-object v3, Lvp/t1;->b:[Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {p0, v0, v1, p1, v3}, Lvp/d4;->c1(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-nez v1, :cond_1

    .line 20
    .line 21
    const/16 p0, 0xd

    .line 22
    .line 23
    return p0

    .line 24
    :cond_1
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Lvp/g1;

    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    const/16 v1, 0x28

    .line 32
    .line 33
    invoke-virtual {p0, v0, v1, p1}, Lvp/d4;->d1(Ljava/lang/String;ILjava/lang/String;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-nez p0, :cond_2

    .line 38
    .line 39
    return v2

    .line 40
    :cond_2
    const/4 p0, 0x0

    .line 41
    return p0
.end method

.method public final f1(Ljava/lang/String;)I
    .locals 4

    .line 1
    const-string v0, "user property"

    .line 2
    .line 3
    invoke-virtual {p0, v0, p1}, Lvp/d4;->b1(Ljava/lang/String;Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x6

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    return v2

    .line 11
    :cond_0
    sget-object v1, Lvp/t1;->i:[Ljava/lang/String;

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-virtual {p0, v0, v1, p1, v3}, Lvp/d4;->c1(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    const/16 p0, 0xf

    .line 21
    .line 22
    return p0

    .line 23
    :cond_1
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v1, Lvp/g1;

    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    const/16 v1, 0x18

    .line 31
    .line 32
    invoke-virtual {p0, v0, v1, p1}, Lvp/d4;->d1(Ljava/lang/String;ILjava/lang/String;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-nez p0, :cond_2

    .line 37
    .line 38
    return v2

    .line 39
    :cond_2
    const/4 p0, 0x0

    .line 40
    return p0
.end method

.method public final g0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;Landroid/os/Bundle;Ljava/util/List;ZZ)I
    .locals 12

    .line 1
    move-object/from16 v3, p4

    .line 2
    .line 3
    iget-object v4, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    move-object v6, v4

    .line 6
    check-cast v6, Lvp/g1;

    .line 7
    .line 8
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 9
    .line 10
    .line 11
    invoke-static {p3}, Lvp/d4;->i1(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    const-string v5, "param"

    .line 16
    .line 17
    const/4 v7, 0x0

    .line 18
    if-eqz v4, :cond_5

    .line 19
    .line 20
    if-eqz p7, :cond_6

    .line 21
    .line 22
    sget-object v4, Lvp/t1;->g:[Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {p2, v4}, Lvp/d4;->z0(Ljava/lang/String;[Ljava/lang/String;)Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    if-nez v4, :cond_0

    .line 29
    .line 30
    const/16 v0, 0x14

    .line 31
    .line 32
    return v0

    .line 33
    :cond_0
    invoke-virtual {v6}, Lvp/g1;->o()Lvp/d3;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    invoke-virtual {v4}, Lvp/x;->a0()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v4}, Lvp/b0;->b0()V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v4}, Lvp/d3;->h0()Z

    .line 44
    .line 45
    .line 46
    move-result v8

    .line 47
    if-nez v8, :cond_1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    iget-object v4, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v4, Lvp/g1;

    .line 53
    .line 54
    iget-object v4, v4, Lvp/g1;->l:Lvp/d4;

    .line 55
    .line 56
    invoke-static {v4}, Lvp/g1;->g(Lap0/o;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v4}, Lvp/d4;->G0()I

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    const v8, 0x310c4

    .line 64
    .line 65
    .line 66
    if-ge v4, v8, :cond_2

    .line 67
    .line 68
    const/16 v0, 0x19

    .line 69
    .line 70
    return v0

    .line 71
    :cond_2
    :goto_0
    instance-of v4, p3, [Landroid/os/Parcelable;

    .line 72
    .line 73
    if-eqz v4, :cond_3

    .line 74
    .line 75
    move-object v8, p3

    .line 76
    check-cast v8, [Landroid/os/Parcelable;

    .line 77
    .line 78
    array-length v8, v8

    .line 79
    goto :goto_1

    .line 80
    :cond_3
    instance-of v8, p3, Ljava/util/ArrayList;

    .line 81
    .line 82
    if-eqz v8, :cond_5

    .line 83
    .line 84
    move-object v8, p3

    .line 85
    check-cast v8, Ljava/util/ArrayList;

    .line 86
    .line 87
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 88
    .line 89
    .line 90
    move-result v8

    .line 91
    :goto_1
    const/16 v9, 0xc8

    .line 92
    .line 93
    if-le v8, v9, :cond_5

    .line 94
    .line 95
    iget-object v10, v6, Lvp/g1;->i:Lvp/p0;

    .line 96
    .line 97
    invoke-static {v10}, Lvp/g1;->k(Lvp/n1;)V

    .line 98
    .line 99
    .line 100
    iget-object v10, v10, Lvp/p0;->o:Lvp/n0;

    .line 101
    .line 102
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 103
    .line 104
    .line 105
    move-result-object v8

    .line 106
    const-string v11, "Parameter array is too long; discarded. Value kind, name, array length"

    .line 107
    .line 108
    invoke-virtual {v10, v11, v5, p2, v8}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    const/16 v8, 0x11

    .line 112
    .line 113
    if-eqz v4, :cond_4

    .line 114
    .line 115
    move-object v4, p3

    .line 116
    check-cast v4, [Landroid/os/Parcelable;

    .line 117
    .line 118
    array-length v10, v4

    .line 119
    if-le v10, v9, :cond_7

    .line 120
    .line 121
    invoke-static {v4, v9}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    check-cast v4, [Landroid/os/Parcelable;

    .line 126
    .line 127
    invoke-virtual {v3, p2, v4}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    .line 128
    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_4
    instance-of v4, p3, Ljava/util/ArrayList;

    .line 132
    .line 133
    if-eqz v4, :cond_7

    .line 134
    .line 135
    move-object v4, p3

    .line 136
    check-cast v4, Ljava/util/ArrayList;

    .line 137
    .line 138
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 139
    .line 140
    .line 141
    move-result v10

    .line 142
    if-le v10, v9, :cond_7

    .line 143
    .line 144
    new-instance v10, Ljava/util/ArrayList;

    .line 145
    .line 146
    invoke-virtual {v4, v7, v9}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 147
    .line 148
    .line 149
    move-result-object v4

    .line 150
    invoke-direct {v10, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v3, p2, v10}, Landroid/os/Bundle;->putParcelableArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 154
    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_5
    move v8, v7

    .line 158
    goto :goto_2

    .line 159
    :cond_6
    const/16 v0, 0x15

    .line 160
    .line 161
    return v0

    .line 162
    :cond_7
    :goto_2
    invoke-static {p1}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 163
    .line 164
    .line 165
    move-result v3

    .line 166
    const/16 v4, 0x1f4

    .line 167
    .line 168
    if-nez v3, :cond_9

    .line 169
    .line 170
    invoke-static {p2}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 171
    .line 172
    .line 173
    move-result v3

    .line 174
    if-eqz v3, :cond_8

    .line 175
    .line 176
    goto :goto_3

    .line 177
    :cond_8
    iget-object v3, v6, Lvp/g1;->g:Lvp/h;

    .line 178
    .line 179
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 180
    .line 181
    .line 182
    goto :goto_4

    .line 183
    :cond_9
    :goto_3
    iget-object v3, v6, Lvp/g1;->g:Lvp/h;

    .line 184
    .line 185
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 186
    .line 187
    .line 188
    const/16 v3, 0x100

    .line 189
    .line 190
    invoke-static {v4, v3}, Ljava/lang/Math;->max(II)I

    .line 191
    .line 192
    .line 193
    move-result v4

    .line 194
    :goto_4
    invoke-virtual {p0, p3, v5, v4, p2}, Lvp/d4;->j1(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)Z

    .line 195
    .line 196
    .line 197
    move-result v3

    .line 198
    if-eqz v3, :cond_a

    .line 199
    .line 200
    goto/16 :goto_8

    .line 201
    .line 202
    :cond_a
    if-eqz p7, :cond_11

    .line 203
    .line 204
    instance-of v3, p3, Landroid/os/Bundle;

    .line 205
    .line 206
    if-eqz v3, :cond_b

    .line 207
    .line 208
    move-object v3, p3

    .line 209
    check-cast v3, Landroid/os/Bundle;

    .line 210
    .line 211
    move-object v0, p0

    .line 212
    move-object v1, p1

    .line 213
    move-object v2, p2

    .line 214
    move-object/from16 v4, p5

    .line 215
    .line 216
    move/from16 v5, p6

    .line 217
    .line 218
    invoke-virtual/range {v0 .. v5}, Lvp/d4;->k1(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;Ljava/util/List;Z)V

    .line 219
    .line 220
    .line 221
    return v8

    .line 222
    :cond_b
    instance-of v0, p3, [Landroid/os/Parcelable;

    .line 223
    .line 224
    if-eqz v0, :cond_d

    .line 225
    .line 226
    move-object v9, p3

    .line 227
    check-cast v9, [Landroid/os/Parcelable;

    .line 228
    .line 229
    array-length v10, v9

    .line 230
    :goto_5
    if-ge v7, v10, :cond_10

    .line 231
    .line 232
    aget-object v0, v9, v7

    .line 233
    .line 234
    instance-of v1, v0, Landroid/os/Bundle;

    .line 235
    .line 236
    if-nez v1, :cond_c

    .line 237
    .line 238
    iget-object v1, v6, Lvp/g1;->i:Lvp/p0;

    .line 239
    .line 240
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 241
    .line 242
    .line 243
    iget-object v1, v1, Lvp/p0;->o:Lvp/n0;

    .line 244
    .line 245
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    const-string v3, "All Parcelable[] elements must be of type Bundle. Value type, name"

    .line 250
    .line 251
    invoke-virtual {v1, v0, p2, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    goto :goto_9

    .line 255
    :cond_c
    move-object v3, v0

    .line 256
    check-cast v3, Landroid/os/Bundle;

    .line 257
    .line 258
    move-object v0, p0

    .line 259
    move-object v1, p1

    .line 260
    move-object v2, p2

    .line 261
    move-object/from16 v4, p5

    .line 262
    .line 263
    move/from16 v5, p6

    .line 264
    .line 265
    invoke-virtual/range {v0 .. v5}, Lvp/d4;->k1(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;Ljava/util/List;Z)V

    .line 266
    .line 267
    .line 268
    add-int/lit8 v7, v7, 0x1

    .line 269
    .line 270
    goto :goto_5

    .line 271
    :cond_d
    instance-of v0, p3, Ljava/util/ArrayList;

    .line 272
    .line 273
    if-eqz v0, :cond_11

    .line 274
    .line 275
    move-object v9, p3

    .line 276
    check-cast v9, Ljava/util/ArrayList;

    .line 277
    .line 278
    invoke-interface {v9}, Ljava/util/List;->size()I

    .line 279
    .line 280
    .line 281
    move-result v10

    .line 282
    :goto_6
    if-ge v7, v10, :cond_10

    .line 283
    .line 284
    invoke-interface {v9, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    instance-of v1, v0, Landroid/os/Bundle;

    .line 289
    .line 290
    if-nez v1, :cond_f

    .line 291
    .line 292
    iget-object v1, v6, Lvp/g1;->i:Lvp/p0;

    .line 293
    .line 294
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 295
    .line 296
    .line 297
    iget-object v1, v1, Lvp/p0;->o:Lvp/n0;

    .line 298
    .line 299
    if-eqz v0, :cond_e

    .line 300
    .line 301
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 302
    .line 303
    .line 304
    move-result-object v0

    .line 305
    goto :goto_7

    .line 306
    :cond_e
    const-string v0, "null"

    .line 307
    .line 308
    :goto_7
    const-string v3, "All ArrayList elements must be of type Bundle. Value type, name"

    .line 309
    .line 310
    invoke-virtual {v1, v0, p2, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    goto :goto_9

    .line 314
    :cond_f
    move-object v3, v0

    .line 315
    check-cast v3, Landroid/os/Bundle;

    .line 316
    .line 317
    move-object v0, p0

    .line 318
    move-object v1, p1

    .line 319
    move-object v2, p2

    .line 320
    move-object/from16 v4, p5

    .line 321
    .line 322
    move/from16 v5, p6

    .line 323
    .line 324
    invoke-virtual/range {v0 .. v5}, Lvp/d4;->k1(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;Ljava/util/List;Z)V

    .line 325
    .line 326
    .line 327
    add-int/lit8 v7, v7, 0x1

    .line 328
    .line 329
    goto :goto_6

    .line 330
    :cond_10
    :goto_8
    return v8

    .line 331
    :cond_11
    :goto_9
    const/4 v0, 0x4

    .line 332
    return v0
.end method

.method public final g1(Ljava/lang/String;)I
    .locals 3

    .line 1
    const-string v0, "event param"

    .line 2
    .line 3
    invoke-virtual {p0, v0, p1}, Lvp/d4;->a1(Ljava/lang/String;Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x3

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    return v2

    .line 11
    :cond_0
    const/4 v1, 0x0

    .line 12
    invoke-virtual {p0, v0, v1, p1, v1}, Lvp/d4;->c1(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    const/16 p0, 0xe

    .line 19
    .line 20
    return p0

    .line 21
    :cond_1
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Lvp/g1;

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    const/16 v1, 0x28

    .line 29
    .line 30
    invoke-virtual {p0, v0, v1, p1}, Lvp/d4;->d1(Ljava/lang/String;ILjava/lang/String;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-nez p0, :cond_2

    .line 35
    .line 36
    return v2

    .line 37
    :cond_2
    const/4 p0, 0x0

    .line 38
    return p0
.end method

.method public final h0(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    const-string v1, "_ev"

    .line 6
    .line 7
    invoke-virtual {v1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/16 v2, 0x100

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    const/16 v4, 0x1f4

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    iget-object p2, v0, Lvp/g1;->g:Lvp/h;

    .line 19
    .line 20
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    invoke-static {v4, v2}, Ljava/lang/Math;->max(II)I

    .line 24
    .line 25
    .line 26
    move-result p2

    .line 27
    invoke-virtual {p0, p2, p1, v3, v3}, Lvp/d4;->U0(ILjava/lang/Object;ZZ)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :cond_0
    invoke-static {p2}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    if-eqz p2, :cond_1

    .line 37
    .line 38
    iget-object p2, v0, Lvp/g1;->g:Lvp/h;

    .line 39
    .line 40
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    invoke-static {v4, v2}, Ljava/lang/Math;->max(II)I

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    goto :goto_0

    .line 48
    :cond_1
    iget-object p2, v0, Lvp/g1;->g:Lvp/h;

    .line 49
    .line 50
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    :goto_0
    const/4 p2, 0x0

    .line 54
    invoke-virtual {p0, v4, p1, p2, v3}, Lvp/d4;->U0(ILjava/lang/Object;ZZ)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method

.method public final h1(Ljava/lang/String;)I
    .locals 3

    .line 1
    const-string v0, "event param"

    .line 2
    .line 3
    invoke-virtual {p0, v0, p1}, Lvp/d4;->b1(Ljava/lang/String;Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x3

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    return v2

    .line 11
    :cond_0
    const/4 v1, 0x0

    .line 12
    invoke-virtual {p0, v0, v1, p1, v1}, Lvp/d4;->c1(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    const/16 p0, 0xe

    .line 19
    .line 20
    return p0

    .line 21
    :cond_1
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Lvp/g1;

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    const/16 v1, 0x28

    .line 29
    .line 30
    invoke-virtual {p0, v0, v1, p1}, Lvp/d4;->d1(Ljava/lang/String;ILjava/lang/String;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-nez p0, :cond_2

    .line 35
    .line 36
    return v2

    .line 37
    :cond_2
    const/4 p0, 0x0

    .line 38
    return p0
.end method

.method public final i0(Ljava/lang/String;Landroid/os/Bundle;Ljava/util/List;Z)Landroid/os/Bundle;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v8, p2

    .line 6
    .line 7
    move-object/from16 v5, p3

    .line 8
    .line 9
    sget-object v2, Lvp/t1;->d:[Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v1, v2}, Lvp/d4;->z0(Ljava/lang/String;[Ljava/lang/String;)Z

    .line 12
    .line 13
    .line 14
    move-result v7

    .line 15
    const/4 v9, 0x0

    .line 16
    if-eqz v8, :cond_f

    .line 17
    .line 18
    new-instance v4, Landroid/os/Bundle;

    .line 19
    .line 20
    invoke-direct {v4, v8}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 21
    .line 22
    .line 23
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v10, v2

    .line 26
    check-cast v10, Lvp/g1;

    .line 27
    .line 28
    iget-object v2, v10, Lvp/g1;->g:Lvp/h;

    .line 29
    .line 30
    iget-object v11, v10, Lvp/g1;->m:Lvp/k0;

    .line 31
    .line 32
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v2, Lvp/g1;

    .line 35
    .line 36
    iget-object v2, v2, Lvp/g1;->l:Lvp/d4;

    .line 37
    .line 38
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 39
    .line 40
    .line 41
    const v3, 0xc02a560

    .line 42
    .line 43
    .line 44
    invoke-virtual {v2, v3}, Lvp/d4;->F0(I)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_0

    .line 49
    .line 50
    const/16 v2, 0x64

    .line 51
    .line 52
    :goto_0
    move v12, v2

    .line 53
    goto :goto_1

    .line 54
    :cond_0
    const/16 v2, 0x19

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :goto_1
    new-instance v2, Ljava/util/TreeSet;

    .line 58
    .line 59
    invoke-virtual {v8}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    invoke-direct {v2, v3}, Ljava/util/TreeSet;-><init>(Ljava/util/Collection;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v2}, Ljava/util/TreeSet;->iterator()Ljava/util/Iterator;

    .line 67
    .line 68
    .line 69
    move-result-object v13

    .line 70
    const/4 v14, 0x0

    .line 71
    move v15, v14

    .line 72
    move/from16 v16, v15

    .line 73
    .line 74
    :goto_2
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    if-eqz v2, :cond_e

    .line 79
    .line 80
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    check-cast v2, Ljava/lang/String;

    .line 85
    .line 86
    if-eqz v5, :cond_2

    .line 87
    .line 88
    invoke-interface {v5, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    if-nez v3, :cond_1

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_1
    move v3, v14

    .line 96
    goto :goto_5

    .line 97
    :cond_2
    :goto_3
    if-nez p4, :cond_3

    .line 98
    .line 99
    invoke-virtual {v0, v2}, Lvp/d4;->g1(Ljava/lang/String;)I

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    goto :goto_4

    .line 104
    :cond_3
    move v3, v14

    .line 105
    :goto_4
    if-nez v3, :cond_4

    .line 106
    .line 107
    invoke-virtual {v0, v2}, Lvp/d4;->h1(Ljava/lang/String;)I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    :cond_4
    :goto_5
    if-eqz v3, :cond_7

    .line 112
    .line 113
    const/4 v6, 0x3

    .line 114
    if-ne v3, v6, :cond_5

    .line 115
    .line 116
    move-object v6, v2

    .line 117
    goto :goto_6

    .line 118
    :cond_5
    move-object v6, v9

    .line 119
    :goto_6
    invoke-virtual {v0, v4, v3, v2, v6}, Lvp/d4;->m0(Landroid/os/Bundle;ILjava/lang/String;Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v4, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    :cond_6
    :goto_7
    move-object/from16 v17, v9

    .line 126
    .line 127
    goto/16 :goto_c

    .line 128
    .line 129
    :cond_7
    invoke-virtual {v8, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v3

    .line 133
    move/from16 v6, p4

    .line 134
    .line 135
    invoke-virtual/range {v0 .. v7}, Lvp/d4;->g0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;Landroid/os/Bundle;Ljava/util/List;ZZ)I

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    const/16 v5, 0x11

    .line 140
    .line 141
    if-ne v3, v5, :cond_8

    .line 142
    .line 143
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 144
    .line 145
    invoke-virtual {v0, v4, v5, v2, v3}, Lvp/d4;->m0(Landroid/os/Bundle;ILjava/lang/String;Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    goto :goto_9

    .line 149
    :cond_8
    if-eqz v3, :cond_a

    .line 150
    .line 151
    const-string v5, "_ev"

    .line 152
    .line 153
    invoke-virtual {v5, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    move-result v5

    .line 157
    if-nez v5, :cond_a

    .line 158
    .line 159
    const/16 v5, 0x15

    .line 160
    .line 161
    if-ne v3, v5, :cond_9

    .line 162
    .line 163
    move-object v5, v1

    .line 164
    goto :goto_8

    .line 165
    :cond_9
    move-object v5, v2

    .line 166
    :goto_8
    invoke-virtual {v8, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v6

    .line 170
    invoke-virtual {v0, v4, v3, v5, v6}, Lvp/d4;->m0(Landroid/os/Bundle;ILjava/lang/String;Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v4, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    goto :goto_7

    .line 177
    :cond_a
    :goto_9
    invoke-static {v2}, Lvp/d4;->Y0(Ljava/lang/String;)Z

    .line 178
    .line 179
    .line 180
    move-result v3

    .line 181
    if-eqz v3, :cond_6

    .line 182
    .line 183
    add-int/lit8 v15, v15, 0x1

    .line 184
    .line 185
    if-le v15, v12, :cond_d

    .line 186
    .line 187
    iget-object v3, v10, Lvp/g1;->g:Lvp/h;

    .line 188
    .line 189
    sget-object v5, Lvp/z;->e1:Lvp/y;

    .line 190
    .line 191
    invoke-virtual {v3, v9, v5}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 192
    .line 193
    .line 194
    move-result v3

    .line 195
    if-eqz v3, :cond_c

    .line 196
    .line 197
    if-nez v16, :cond_b

    .line 198
    .line 199
    goto :goto_a

    .line 200
    :cond_b
    move-object/from16 v17, v9

    .line 201
    .line 202
    goto :goto_b

    .line 203
    :cond_c
    :goto_a
    invoke-static {v12}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v3

    .line 207
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 208
    .line 209
    .line 210
    move-result v3

    .line 211
    new-instance v5, Ljava/lang/StringBuilder;

    .line 212
    .line 213
    add-int/lit8 v3, v3, 0x25

    .line 214
    .line 215
    invoke-direct {v5, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 216
    .line 217
    .line 218
    const-string v3, "Event can\'t contain more than "

    .line 219
    .line 220
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 221
    .line 222
    .line 223
    invoke-virtual {v5, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 224
    .line 225
    .line 226
    const-string v3, " params"

    .line 227
    .line 228
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v3

    .line 235
    iget-object v5, v10, Lvp/g1;->i:Lvp/p0;

    .line 236
    .line 237
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 238
    .line 239
    .line 240
    iget-object v5, v5, Lvp/p0;->l:Lvp/n0;

    .line 241
    .line 242
    invoke-virtual {v11, v1}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object v6

    .line 246
    move-object/from16 v17, v9

    .line 247
    .line 248
    invoke-virtual {v11, v8}, Lvp/k0;->e(Landroid/os/Bundle;)Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object v9

    .line 252
    invoke-virtual {v5, v6, v9, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    :goto_b
    const/4 v3, 0x5

    .line 256
    invoke-static {v3, v4}, Lvp/d4;->T0(ILandroid/os/Bundle;)Z

    .line 257
    .line 258
    .line 259
    invoke-virtual {v4, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 260
    .line 261
    .line 262
    const/16 v16, 0x1

    .line 263
    .line 264
    :goto_c
    move-object/from16 v5, p3

    .line 265
    .line 266
    move-object/from16 v9, v17

    .line 267
    .line 268
    goto/16 :goto_2

    .line 269
    .line 270
    :cond_d
    move-object/from16 v5, p3

    .line 271
    .line 272
    goto/16 :goto_2

    .line 273
    .line 274
    :cond_e
    return-object v4

    .line 275
    :cond_f
    move-object/from16 v17, v9

    .line 276
    .line 277
    return-object v17
.end method

.method public final j0(Lh01/q;I)V
    .locals 10

    .line 1
    new-instance v0, Ljava/util/TreeSet;

    .line 2
    .line 3
    iget-object v1, p1, Lh01/q;->h:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Landroid/os/Bundle;

    .line 6
    .line 7
    invoke-virtual {v1}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-direct {v0, v2}, Ljava/util/TreeSet;-><init>(Ljava/util/Collection;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/util/TreeSet;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v2, 0x0

    .line 19
    move v3, v2

    .line 20
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_3

    .line 25
    .line 26
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    check-cast v4, Ljava/lang/String;

    .line 31
    .line 32
    invoke-static {v4}, Lvp/d4;->Y0(Ljava/lang/String;)Z

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    if-eqz v5, :cond_0

    .line 37
    .line 38
    add-int/lit8 v2, v2, 0x1

    .line 39
    .line 40
    if-le v2, p2, :cond_0

    .line 41
    .line 42
    iget-object v5, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v5, Lvp/g1;

    .line 45
    .line 46
    iget-object v6, v5, Lvp/g1;->g:Lvp/h;

    .line 47
    .line 48
    iget-object v7, v5, Lvp/g1;->m:Lvp/k0;

    .line 49
    .line 50
    const/4 v8, 0x0

    .line 51
    sget-object v9, Lvp/z;->e1:Lvp/y;

    .line 52
    .line 53
    invoke-virtual {v6, v8, v9}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 54
    .line 55
    .line 56
    move-result v6

    .line 57
    if-eqz v6, :cond_1

    .line 58
    .line 59
    if-nez v3, :cond_2

    .line 60
    .line 61
    :cond_1
    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    new-instance v6, Ljava/lang/StringBuilder;

    .line 70
    .line 71
    add-int/lit8 v3, v3, 0x25

    .line 72
    .line 73
    invoke-direct {v6, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 74
    .line 75
    .line 76
    const-string v3, "Event can\'t contain more than "

    .line 77
    .line 78
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v6, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v3, " params"

    .line 85
    .line 86
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    iget-object v5, v5, Lvp/g1;->i:Lvp/p0;

    .line 94
    .line 95
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 96
    .line 97
    .line 98
    iget-object v5, v5, Lvp/p0;->l:Lvp/n0;

    .line 99
    .line 100
    iget-object v6, p1, Lh01/q;->f:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v6, Ljava/lang/String;

    .line 103
    .line 104
    invoke-virtual {v7, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    invoke-virtual {v7, v1}, Lvp/k0;->e(Landroid/os/Bundle;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v7

    .line 112
    invoke-virtual {v5, v6, v7, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    const/4 v3, 0x5

    .line 116
    invoke-static {v3, v1}, Lvp/d4;->T0(ILandroid/os/Bundle;)Z

    .line 117
    .line 118
    .line 119
    :cond_2
    invoke-virtual {v1, v4}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    const/4 v3, 0x1

    .line 123
    goto :goto_0

    .line 124
    :cond_3
    return-void
.end method

.method public final j1(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    goto :goto_1

    .line 5
    :cond_0
    instance-of v1, p1, Ljava/lang/Long;

    .line 6
    .line 7
    if-nez v1, :cond_4

    .line 8
    .line 9
    instance-of v1, p1, Ljava/lang/Float;

    .line 10
    .line 11
    if-nez v1, :cond_4

    .line 12
    .line 13
    instance-of v1, p1, Ljava/lang/Integer;

    .line 14
    .line 15
    if-nez v1, :cond_4

    .line 16
    .line 17
    instance-of v1, p1, Ljava/lang/Byte;

    .line 18
    .line 19
    if-nez v1, :cond_4

    .line 20
    .line 21
    instance-of v1, p1, Ljava/lang/Short;

    .line 22
    .line 23
    if-nez v1, :cond_4

    .line 24
    .line 25
    instance-of v1, p1, Ljava/lang/Boolean;

    .line 26
    .line 27
    if-nez v1, :cond_4

    .line 28
    .line 29
    instance-of v1, p1, Ljava/lang/Double;

    .line 30
    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    return v0

    .line 34
    :cond_1
    instance-of v1, p1, Ljava/lang/String;

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    instance-of v1, p1, Ljava/lang/Character;

    .line 40
    .line 41
    if-nez v1, :cond_3

    .line 42
    .line 43
    instance-of v1, p1, Ljava/lang/CharSequence;

    .line 44
    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    return v2

    .line 49
    :cond_3
    :goto_0
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    invoke-virtual {p1, v2, v1}, Ljava/lang/String;->codePointCount(II)I

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-le v1, p3, :cond_4

    .line 62
    .line 63
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p0, Lvp/g1;

    .line 66
    .line 67
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 68
    .line 69
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 70
    .line 71
    .line 72
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 73
    .line 74
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    const-string p3, "Value is too long; discarded. Value kind, name, value length"

    .line 83
    .line 84
    invoke-virtual {p0, p3, p2, p4, p1}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    return v2

    .line 88
    :cond_4
    :goto_1
    return v0
.end method

.method public final k0([Landroid/os/Parcelable;I)V
    .locals 13

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    array-length v0, p1

    .line 5
    const/4 v1, 0x0

    .line 6
    move v2, v1

    .line 7
    :goto_0
    if-ge v2, v0, :cond_4

    .line 8
    .line 9
    aget-object v3, p1, v2

    .line 10
    .line 11
    check-cast v3, Landroid/os/Bundle;

    .line 12
    .line 13
    new-instance v4, Ljava/util/TreeSet;

    .line 14
    .line 15
    invoke-virtual {v3}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 16
    .line 17
    .line 18
    move-result-object v5

    .line 19
    invoke-direct {v4, v5}, Ljava/util/TreeSet;-><init>(Ljava/util/Collection;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v4}, Ljava/util/TreeSet;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    move v5, v1

    .line 27
    move v6, v5

    .line 28
    :cond_0
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v7

    .line 32
    if-eqz v7, :cond_3

    .line 33
    .line 34
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v7

    .line 38
    check-cast v7, Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {v7}, Lvp/d4;->Y0(Ljava/lang/String;)Z

    .line 41
    .line 42
    .line 43
    move-result v8

    .line 44
    if-eqz v8, :cond_0

    .line 45
    .line 46
    sget-object v8, Lvp/t1;->h:[Ljava/lang/String;

    .line 47
    .line 48
    invoke-static {v7, v8}, Lvp/d4;->z0(Ljava/lang/String;[Ljava/lang/String;)Z

    .line 49
    .line 50
    .line 51
    move-result v8

    .line 52
    if-nez v8, :cond_0

    .line 53
    .line 54
    add-int/lit8 v5, v5, 0x1

    .line 55
    .line 56
    if-le v5, p2, :cond_0

    .line 57
    .line 58
    iget-object v8, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v8, Lvp/g1;

    .line 61
    .line 62
    iget-object v9, v8, Lvp/g1;->g:Lvp/h;

    .line 63
    .line 64
    iget-object v10, v8, Lvp/g1;->m:Lvp/k0;

    .line 65
    .line 66
    const/4 v11, 0x0

    .line 67
    sget-object v12, Lvp/z;->e1:Lvp/y;

    .line 68
    .line 69
    invoke-virtual {v9, v11, v12}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 70
    .line 71
    .line 72
    move-result v9

    .line 73
    if-eqz v9, :cond_1

    .line 74
    .line 75
    if-nez v6, :cond_2

    .line 76
    .line 77
    :cond_1
    iget-object v6, v8, Lvp/g1;->i:Lvp/p0;

    .line 78
    .line 79
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 80
    .line 81
    .line 82
    iget-object v6, v6, Lvp/p0;->l:Lvp/n0;

    .line 83
    .line 84
    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v8

    .line 88
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 89
    .line 90
    .line 91
    move-result v8

    .line 92
    new-instance v9, Ljava/lang/StringBuilder;

    .line 93
    .line 94
    add-int/lit8 v8, v8, 0x3c

    .line 95
    .line 96
    invoke-direct {v9, v8}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 97
    .line 98
    .line 99
    const-string v8, "Param can\'t contain more than "

    .line 100
    .line 101
    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v9, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    const-string v8, " item-scoped custom parameters"

    .line 108
    .line 109
    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v8

    .line 116
    invoke-virtual {v10, v7}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v9

    .line 120
    invoke-virtual {v10, v3}, Lvp/k0;->e(Landroid/os/Bundle;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v10

    .line 124
    invoke-virtual {v6, v9, v10, v8}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    :cond_2
    const/16 v6, 0x1c

    .line 128
    .line 129
    invoke-static {v6, v3}, Lvp/d4;->T0(ILandroid/os/Bundle;)Z

    .line 130
    .line 131
    .line 132
    invoke-virtual {v3, v7}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    const/4 v6, 0x1

    .line 136
    goto :goto_1

    .line 137
    :cond_3
    add-int/lit8 v2, v2, 0x1

    .line 138
    .line 139
    goto/16 :goto_0

    .line 140
    .line 141
    :cond_4
    return-void
.end method

.method public final k1(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;Ljava/util/List;Z)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v4, p3

    .line 6
    .line 7
    move-object/from16 v5, p4

    .line 8
    .line 9
    if-nez v4, :cond_0

    .line 10
    .line 11
    goto/16 :goto_9

    .line 12
    .line 13
    :cond_0
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v8, v2

    .line 16
    check-cast v8, Lvp/g1;

    .line 17
    .line 18
    iget-object v2, v8, Lvp/g1;->g:Lvp/h;

    .line 19
    .line 20
    iget-object v9, v8, Lvp/g1;->i:Lvp/p0;

    .line 21
    .line 22
    iget-object v10, v8, Lvp/g1;->m:Lvp/k0;

    .line 23
    .line 24
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v2, Lvp/g1;

    .line 27
    .line 28
    iget-object v2, v2, Lvp/g1;->l:Lvp/d4;

    .line 29
    .line 30
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 31
    .line 32
    .line 33
    const v11, 0xdc64e60

    .line 34
    .line 35
    .line 36
    invoke-virtual {v2, v11}, Lvp/d4;->F0(I)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    const/4 v13, 0x1

    .line 41
    if-eq v13, v2, :cond_1

    .line 42
    .line 43
    const/4 v14, 0x0

    .line 44
    goto :goto_0

    .line 45
    :cond_1
    const/16 v2, 0x23

    .line 46
    .line 47
    move v14, v2

    .line 48
    :goto_0
    new-instance v2, Ljava/util/TreeSet;

    .line 49
    .line 50
    invoke-virtual {v4}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    invoke-direct {v2, v3}, Ljava/util/TreeSet;-><init>(Ljava/util/Collection;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v2}, Ljava/util/TreeSet;->iterator()Ljava/util/Iterator;

    .line 58
    .line 59
    .line 60
    move-result-object v15

    .line 61
    const/16 v16, 0x0

    .line 62
    .line 63
    const/16 v17, 0x0

    .line 64
    .line 65
    :goto_1
    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    if-eqz v2, :cond_f

    .line 70
    .line 71
    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    check-cast v2, Ljava/lang/String;

    .line 76
    .line 77
    if-eqz v5, :cond_3

    .line 78
    .line 79
    invoke-interface {v5, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-nez v3, :cond_2

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_2
    const/4 v3, 0x0

    .line 87
    goto :goto_4

    .line 88
    :cond_3
    :goto_2
    if-nez p5, :cond_4

    .line 89
    .line 90
    invoke-virtual {v0, v2}, Lvp/d4;->g1(Ljava/lang/String;)I

    .line 91
    .line 92
    .line 93
    move-result v3

    .line 94
    goto :goto_3

    .line 95
    :cond_4
    const/4 v3, 0x0

    .line 96
    :goto_3
    if-nez v3, :cond_5

    .line 97
    .line 98
    invoke-virtual {v0, v2}, Lvp/d4;->h1(Ljava/lang/String;)I

    .line 99
    .line 100
    .line 101
    move-result v3

    .line 102
    :cond_5
    :goto_4
    const/4 v6, 0x0

    .line 103
    if-eqz v3, :cond_7

    .line 104
    .line 105
    const/4 v7, 0x3

    .line 106
    if-ne v3, v7, :cond_6

    .line 107
    .line 108
    move-object v6, v2

    .line 109
    :cond_6
    invoke-virtual {v0, v4, v3, v2, v6}, Lvp/d4;->m0(Landroid/os/Bundle;ILjava/lang/String;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v4, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    move-object/from16 v12, p2

    .line 116
    .line 117
    goto/16 :goto_8

    .line 118
    .line 119
    :cond_7
    invoke-virtual {v4, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    invoke-static {v3}, Lvp/d4;->i1(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v3

    .line 127
    if-eqz v3, :cond_8

    .line 128
    .line 129
    invoke-static {v9}, Lvp/g1;->k(Lvp/n1;)V

    .line 130
    .line 131
    .line 132
    iget-object v3, v9, Lvp/p0;->o:Lvp/n0;

    .line 133
    .line 134
    const-string v7, "Nested Bundle parameters are not allowed; discarded. event name, param name, child param name"

    .line 135
    .line 136
    move-object/from16 v12, p2

    .line 137
    .line 138
    invoke-virtual {v3, v7, v1, v12, v2}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    const/16 v3, 0x16

    .line 142
    .line 143
    move-object v13, v6

    .line 144
    goto :goto_5

    .line 145
    :cond_8
    move-object/from16 v12, p2

    .line 146
    .line 147
    invoke-virtual {v4, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v3

    .line 151
    const/4 v7, 0x0

    .line 152
    move-object v13, v6

    .line 153
    move/from16 v6, p5

    .line 154
    .line 155
    invoke-virtual/range {v0 .. v7}, Lvp/d4;->g0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;Landroid/os/Bundle;Ljava/util/List;ZZ)I

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    :goto_5
    if-eqz v3, :cond_9

    .line 160
    .line 161
    const-string v5, "_ev"

    .line 162
    .line 163
    invoke-virtual {v5, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v5

    .line 167
    if-nez v5, :cond_9

    .line 168
    .line 169
    invoke-virtual {v4, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v5

    .line 173
    invoke-virtual {v0, v4, v3, v2, v5}, Lvp/d4;->m0(Landroid/os/Bundle;ILjava/lang/String;Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {v4, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    goto/16 :goto_8

    .line 180
    .line 181
    :cond_9
    invoke-static {v2}, Lvp/d4;->Y0(Ljava/lang/String;)Z

    .line 182
    .line 183
    .line 184
    move-result v3

    .line 185
    if-eqz v3, :cond_e

    .line 186
    .line 187
    sget-object v3, Lvp/t1;->h:[Ljava/lang/String;

    .line 188
    .line 189
    invoke-static {v2, v3}, Lvp/d4;->z0(Ljava/lang/String;[Ljava/lang/String;)Z

    .line 190
    .line 191
    .line 192
    move-result v3

    .line 193
    if-nez v3, :cond_e

    .line 194
    .line 195
    add-int/lit8 v3, v16, 0x1

    .line 196
    .line 197
    invoke-virtual {v0, v11}, Lvp/d4;->F0(I)Z

    .line 198
    .line 199
    .line 200
    move-result v5

    .line 201
    if-nez v5, :cond_a

    .line 202
    .line 203
    invoke-static {v9}, Lvp/g1;->k(Lvp/n1;)V

    .line 204
    .line 205
    .line 206
    iget-object v5, v9, Lvp/p0;->l:Lvp/n0;

    .line 207
    .line 208
    invoke-virtual {v10, v1}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object v6

    .line 212
    invoke-virtual {v10, v4}, Lvp/k0;->e(Landroid/os/Bundle;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v7

    .line 216
    const-string v13, "Item array not supported on client\'s version of Google Play Services (Android Only)"

    .line 217
    .line 218
    invoke-virtual {v5, v6, v7, v13}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    const/16 v5, 0x17

    .line 222
    .line 223
    invoke-static {v5, v4}, Lvp/d4;->T0(ILandroid/os/Bundle;)Z

    .line 224
    .line 225
    .line 226
    invoke-virtual {v4, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    goto :goto_6

    .line 230
    :cond_a
    if-le v3, v14, :cond_d

    .line 231
    .line 232
    iget-object v5, v8, Lvp/g1;->g:Lvp/h;

    .line 233
    .line 234
    sget-object v6, Lvp/z;->e1:Lvp/y;

    .line 235
    .line 236
    invoke-virtual {v5, v13, v6}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 237
    .line 238
    .line 239
    move-result v5

    .line 240
    if-eqz v5, :cond_b

    .line 241
    .line 242
    if-nez v17, :cond_c

    .line 243
    .line 244
    :cond_b
    invoke-static {v9}, Lvp/g1;->k(Lvp/n1;)V

    .line 245
    .line 246
    .line 247
    iget-object v5, v9, Lvp/p0;->l:Lvp/n0;

    .line 248
    .line 249
    invoke-static {v14}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 250
    .line 251
    .line 252
    move-result-object v6

    .line 253
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 254
    .line 255
    .line 256
    move-result v6

    .line 257
    new-instance v7, Ljava/lang/StringBuilder;

    .line 258
    .line 259
    add-int/lit8 v6, v6, 0x37

    .line 260
    .line 261
    invoke-direct {v7, v6}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 262
    .line 263
    .line 264
    const-string v6, "Item can\'t contain more than "

    .line 265
    .line 266
    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 267
    .line 268
    .line 269
    invoke-virtual {v7, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 270
    .line 271
    .line 272
    const-string v6, " item-scoped custom params"

    .line 273
    .line 274
    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 275
    .line 276
    .line 277
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object v6

    .line 281
    invoke-virtual {v10, v1}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v7

    .line 285
    invoke-virtual {v10, v4}, Lvp/k0;->e(Landroid/os/Bundle;)Ljava/lang/String;

    .line 286
    .line 287
    .line 288
    move-result-object v13

    .line 289
    invoke-virtual {v5, v7, v13, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    :cond_c
    const/16 v5, 0x1c

    .line 293
    .line 294
    invoke-static {v5, v4}, Lvp/d4;->T0(ILandroid/os/Bundle;)Z

    .line 295
    .line 296
    .line 297
    invoke-virtual {v4, v2}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    move-object/from16 v5, p4

    .line 301
    .line 302
    move/from16 v16, v3

    .line 303
    .line 304
    const/4 v13, 0x1

    .line 305
    const/16 v17, 0x1

    .line 306
    .line 307
    goto/16 :goto_1

    .line 308
    .line 309
    :cond_d
    :goto_6
    move-object/from16 v5, p4

    .line 310
    .line 311
    move/from16 v16, v3

    .line 312
    .line 313
    :goto_7
    const/4 v13, 0x1

    .line 314
    goto/16 :goto_1

    .line 315
    .line 316
    :cond_e
    :goto_8
    move-object/from16 v5, p4

    .line 317
    .line 318
    goto :goto_7

    .line 319
    :cond_f
    :goto_9
    return-void
.end method

.method public final l0(Landroid/os/Bundle;Landroid/os/Bundle;)V
    .locals 4

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    invoke-virtual {p2}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_2

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {p1, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-nez v2, :cond_1

    .line 29
    .line 30
    iget-object v2, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v2, Lvp/g1;

    .line 33
    .line 34
    iget-object v2, v2, Lvp/g1;->l:Lvp/d4;

    .line 35
    .line 36
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p2, v1}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    invoke-virtual {v2, p1, v1, v3}, Lvp/d4;->p0(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_2
    :goto_1
    return-void
.end method

.method public final m0(Landroid/os/Bundle;ILjava/lang/String;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p2, p1}, Lvp/d4;->T0(ILandroid/os/Bundle;)Z

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-eqz p2, :cond_1

    .line 6
    .line 7
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lvp/g1;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/16 p0, 0x28

    .line 15
    .line 16
    const/4 p2, 0x1

    .line 17
    invoke-static {p3, p0, p2}, Lvp/d4;->f0(Ljava/lang/String;IZ)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const-string p2, "_ev"

    .line 22
    .line 23
    invoke-virtual {p1, p2, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    if-eqz p4, :cond_1

    .line 27
    .line 28
    instance-of p0, p4, Ljava/lang/String;

    .line 29
    .line 30
    if-nez p0, :cond_0

    .line 31
    .line 32
    instance-of p0, p4, Ljava/lang/CharSequence;

    .line 33
    .line 34
    if-eqz p0, :cond_1

    .line 35
    .line 36
    :cond_0
    invoke-virtual {p4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    const-string p2, "_el"

    .line 45
    .line 46
    int-to-long p3, p0

    .line 47
    invoke-virtual {p1, p2, p3, p4}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 48
    .line 49
    .line 50
    :cond_1
    return-void
.end method

.method public final n0(Ljava/lang/Object;Ljava/lang/String;)I
    .locals 2

    .line 1
    const-string v0, "_ldl"

    .line 2
    .line 3
    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, p2}, Lvp/d4;->V0(Ljava/lang/String;)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const-string v1, "user property referrer"

    .line 14
    .line 15
    invoke-virtual {p0, p1, v1, v0, p2}, Lvp/d4;->j1(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-virtual {p0, p2}, Lvp/d4;->V0(Ljava/lang/String;)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const-string v1, "user property"

    .line 25
    .line 26
    invoke-virtual {p0, p1, v1, v0, p2}, Lvp/d4;->j1(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    :goto_0
    if-eqz p0, :cond_1

    .line 31
    .line 32
    const/4 p0, 0x0

    .line 33
    return p0

    .line 34
    :cond_1
    const/4 p0, 0x7

    .line 35
    return p0
.end method

.method public final o0(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "_ldl"

    .line 2
    .line 3
    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, p2}, Lvp/d4;->V0(Ljava/lang/String;)I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    const/4 v0, 0x1

    .line 15
    invoke-virtual {p0, p2, p1, v0, v1}, Lvp/d4;->U0(ILjava/lang/Object;ZZ)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    invoke-virtual {p0, p2}, Lvp/d4;->V0(Ljava/lang/String;)I

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    invoke-virtual {p0, p2, p1, v1, v1}, Lvp/d4;->U0(ILjava/lang/Object;ZZ)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method public final p0(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p3, Ljava/lang/Long;

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    check-cast p3, Ljava/lang/Long;

    .line 9
    .line 10
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    invoke-virtual {p1, p2, v0, v1}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_1
    instance-of v0, p3, Ljava/lang/String;

    .line 19
    .line 20
    if-eqz v0, :cond_2

    .line 21
    .line 22
    invoke-static {p3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {p1, p2, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_2
    instance-of v0, p3, Ljava/lang/Double;

    .line 31
    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    check-cast p3, Ljava/lang/Double;

    .line 35
    .line 36
    invoke-virtual {p3}, Ljava/lang/Double;->doubleValue()D

    .line 37
    .line 38
    .line 39
    move-result-wide v0

    .line 40
    invoke-virtual {p1, p2, v0, v1}, Landroid/os/BaseBundle;->putDouble(Ljava/lang/String;D)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_3
    instance-of v0, p3, [Landroid/os/Bundle;

    .line 45
    .line 46
    if-eqz v0, :cond_4

    .line 47
    .line 48
    check-cast p3, [Landroid/os/Bundle;

    .line 49
    .line 50
    invoke-virtual {p1, p2, p3}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :cond_4
    if-eqz p2, :cond_6

    .line 55
    .line 56
    if-eqz p3, :cond_5

    .line 57
    .line 58
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    goto :goto_0

    .line 67
    :cond_5
    const/4 p1, 0x0

    .line 68
    :goto_0
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p0, Lvp/g1;

    .line 71
    .line 72
    iget-object p3, p0, Lvp/g1;->i:Lvp/p0;

    .line 73
    .line 74
    invoke-static {p3}, Lvp/g1;->k(Lvp/n1;)V

    .line 75
    .line 76
    .line 77
    iget-object p3, p3, Lvp/p0;->o:Lvp/n0;

    .line 78
    .line 79
    iget-object p0, p0, Lvp/g1;->m:Lvp/k0;

    .line 80
    .line 81
    invoke-virtual {p0, p2}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    const-string p2, "Not putting event parameter. Invalid value type. name, type"

    .line 86
    .line 87
    invoke-virtual {p3, p0, p1, p2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    :cond_6
    :goto_1
    return-void
.end method

.method public final u0()Lga/a;
    .locals 9

    .line 1
    iget-object v0, p0, Lvp/d4;->j:Lga/a;

    .line 2
    .line 3
    if-nez v0, :cond_9

    .line 4
    .line 5
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lvp/g1;

    .line 8
    .line 9
    iget-object v0, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 10
    .line 11
    const-string v1, "context"

    .line 12
    .line 13
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "AdServicesInfo.version="

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 24
    .line 25
    sget-object v3, Lea/b;->a:Lea/b;

    .line 26
    .line 27
    const/4 v4, 0x0

    .line 28
    const/16 v5, 0x21

    .line 29
    .line 30
    if-lt v2, v5, :cond_0

    .line 31
    .line 32
    invoke-virtual {v3}, Lea/b;->a()I

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v6, v4

    .line 38
    :goto_0
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    const-string v6, "MeasurementManager"

    .line 46
    .line 47
    invoke-static {v6, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 48
    .line 49
    .line 50
    if-lt v2, v5, :cond_1

    .line 51
    .line 52
    invoke-virtual {v3}, Lea/b;->a()I

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    goto :goto_1

    .line 57
    :cond_1
    move v1, v4

    .line 58
    :goto_1
    const/4 v3, 0x5

    .line 59
    const/4 v5, 0x0

    .line 60
    if-lt v1, v3, :cond_2

    .line 61
    .line 62
    new-instance v1, Lha/b;

    .line 63
    .line 64
    invoke-static {}, Lc2/h;->p()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    invoke-virtual {v0, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    const-string v2, "context.getSystemService\u2026ementManager::class.java)"

    .line 73
    .line 74
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-static {v0}, Lc2/h;->d(Ljava/lang/Object;)Landroid/adservices/measurement/MeasurementManager;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-direct {v1, v0}, Lha/d;-><init>(Landroid/adservices/measurement/MeasurementManager;)V

    .line 82
    .line 83
    .line 84
    goto :goto_5

    .line 85
    :cond_2
    sget-object v1, Lea/a;->a:Lea/a;

    .line 86
    .line 87
    const/16 v3, 0x20

    .line 88
    .line 89
    const/16 v7, 0x1f

    .line 90
    .line 91
    if-eq v2, v7, :cond_4

    .line 92
    .line 93
    if-ne v2, v3, :cond_3

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_3
    move v2, v4

    .line 97
    goto :goto_3

    .line 98
    :cond_4
    :goto_2
    invoke-virtual {v1}, Lea/a;->a()I

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    :goto_3
    const/16 v8, 0x9

    .line 103
    .line 104
    if-lt v2, v8, :cond_7

    .line 105
    .line 106
    new-instance v2, La3/f;

    .line 107
    .line 108
    const/16 v8, 0x12

    .line 109
    .line 110
    invoke-direct {v2, v0, v8}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 111
    .line 112
    .line 113
    :try_start_0
    invoke-virtual {v2, v0}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_0 .. :try_end_0} :catch_0

    .line 117
    goto :goto_4

    .line 118
    :catch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 119
    .line 120
    const-string v2, "Unable to find adservices code, check manifest for uses-library tag, versionS="

    .line 121
    .line 122
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 126
    .line 127
    if-eq v2, v7, :cond_5

    .line 128
    .line 129
    if-ne v2, v3, :cond_6

    .line 130
    .line 131
    :cond_5
    invoke-virtual {v1}, Lea/a;->a()I

    .line 132
    .line 133
    .line 134
    move-result v4

    .line 135
    :cond_6
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    invoke-static {v6, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 143
    .line 144
    .line 145
    move-object v0, v5

    .line 146
    :goto_4
    move-object v1, v0

    .line 147
    check-cast v1, Lha/d;

    .line 148
    .line 149
    goto :goto_5

    .line 150
    :cond_7
    move-object v1, v5

    .line 151
    :goto_5
    if-eqz v1, :cond_8

    .line 152
    .line 153
    new-instance v5, Lga/a;

    .line 154
    .line 155
    invoke-direct {v5, v1}, Lga/a;-><init>(Lha/d;)V

    .line 156
    .line 157
    .line 158
    :cond_8
    iput-object v5, p0, Lvp/d4;->j:Lga/a;

    .line 159
    .line 160
    :cond_9
    iget-object p0, p0, Lvp/d4;->j:Lga/a;

    .line 161
    .line 162
    return-object p0
.end method

.method public final v0()J
    .locals 11

    .line 1
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lvp/g1;

    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/g1;->q()Lvp/h0;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 13
    .line 14
    invoke-virtual {v1}, Lvp/h0;->g0()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-static {v1}, Lvp/d4;->w0(Ljava/lang/String;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    const-wide/16 v2, 0x0

    .line 23
    .line 24
    if-nez v1, :cond_0

    .line 25
    .line 26
    return-wide v2

    .line 27
    :cond_0
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 28
    .line 29
    const/4 v4, 0x0

    .line 30
    const/4 v5, 0x0

    .line 31
    const/16 v6, 0x1e

    .line 32
    .line 33
    if-ge v1, v6, :cond_1

    .line 34
    .line 35
    const-wide/16 v6, 0x4

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    invoke-static {}, Ld6/t1;->D()I

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    const/4 v8, 0x4

    .line 43
    if-ge v7, v8, :cond_2

    .line 44
    .line 45
    const-wide/16 v6, 0x8

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    if-lt v1, v6, :cond_3

    .line 49
    .line 50
    invoke-static {}, Ld6/t1;->D()I

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    const/4 v6, 0x3

    .line 55
    if-le v1, v6, :cond_3

    .line 56
    .line 57
    invoke-static {}, Ld6/t1;->C()I

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    goto :goto_0

    .line 62
    :cond_3
    move v1, v4

    .line 63
    :goto_0
    sget-object v6, Lvp/z;->l0:Lvp/y;

    .line 64
    .line 65
    invoke-virtual {v6, v5}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    check-cast v6, Ljava/lang/Integer;

    .line 70
    .line 71
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 72
    .line 73
    .line 74
    move-result v6

    .line 75
    if-ge v1, v6, :cond_4

    .line 76
    .line 77
    const-wide/16 v6, 0x10

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_4
    move-wide v6, v2

    .line 81
    :goto_1
    const-string v1, "android.permission.ACCESS_ADSERVICES_ATTRIBUTION"

    .line 82
    .line 83
    invoke-virtual {p0, v1}, Lvp/d4;->x0(Ljava/lang/String;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_5

    .line 88
    .line 89
    const-wide/16 v8, 0x2

    .line 90
    .line 91
    or-long/2addr v6, v8

    .line 92
    :cond_5
    cmp-long v1, v6, v2

    .line 93
    .line 94
    if-nez v1, :cond_9

    .line 95
    .line 96
    iget-object v1, p0, Lvp/d4;->k:Ljava/lang/Boolean;

    .line 97
    .line 98
    if-nez v1, :cond_8

    .line 99
    .line 100
    invoke-virtual {p0}, Lvp/d4;->u0()Lga/a;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    if-nez v1, :cond_6

    .line 105
    .line 106
    goto :goto_6

    .line 107
    :cond_6
    invoke-virtual {v1}, Lga/a;->b()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    :try_start_0
    sget-object v8, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 112
    .line 113
    const-wide/16 v9, 0x2710

    .line 114
    .line 115
    invoke-interface {v1, v9, v10, v8}, Ljava/util/concurrent/Future;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    check-cast v1, Ljava/lang/Integer;
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_0 .. :try_end_0} :catch_1

    .line 120
    .line 121
    if-eqz v1, :cond_7

    .line 122
    .line 123
    :try_start_1
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 124
    .line 125
    .line 126
    move-result v5

    .line 127
    const/4 v8, 0x1

    .line 128
    if-ne v5, v8, :cond_7

    .line 129
    .line 130
    move v4, v8

    .line 131
    goto :goto_2

    .line 132
    :catch_0
    move-exception v4

    .line 133
    goto :goto_3

    .line 134
    :cond_7
    :goto_2
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 135
    .line 136
    .line 137
    move-result-object v4

    .line 138
    iput-object v4, p0, Lvp/d4;->k:Ljava/lang/Boolean;
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_1 .. :try_end_1} :catch_0

    .line 139
    .line 140
    goto :goto_5

    .line 141
    :goto_3
    move-object v5, v1

    .line 142
    goto :goto_4

    .line 143
    :catch_1
    move-exception v1

    .line 144
    move-object v4, v1

    .line 145
    :goto_4
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 146
    .line 147
    .line 148
    iget-object v1, v0, Lvp/p0;->m:Lvp/n0;

    .line 149
    .line 150
    const-string v8, "Measurement manager api exception"

    .line 151
    .line 152
    invoke-virtual {v1, v4, v8}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 156
    .line 157
    iput-object v1, p0, Lvp/d4;->k:Ljava/lang/Boolean;

    .line 158
    .line 159
    move-object v1, v5

    .line 160
    :goto_5
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 161
    .line 162
    .line 163
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 164
    .line 165
    const-string v4, "Measurement manager api status result"

    .line 166
    .line 167
    invoke-virtual {v0, v1, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    :cond_8
    iget-object p0, p0, Lvp/d4;->k:Ljava/lang/Boolean;

    .line 171
    .line 172
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 173
    .line 174
    .line 175
    move-result v4

    .line 176
    :goto_6
    if-nez v4, :cond_9

    .line 177
    .line 178
    const-wide/16 v6, 0x40

    .line 179
    .line 180
    :cond_9
    cmp-long p0, v6, v2

    .line 181
    .line 182
    if-nez p0, :cond_a

    .line 183
    .line 184
    const-wide/16 v0, 0x1

    .line 185
    .line 186
    return-wide v0

    .line 187
    :cond_a
    return-wide v6
.end method

.method public final x0(Ljava/lang/String;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lap0/o;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lvp/g1;

    .line 7
    .line 8
    iget-object v0, p0, Lvp/g1;->d:Landroid/content/Context;

    .line 9
    .line 10
    invoke-static {v0}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object v0, v0, Lcq/r1;->d:Landroid/content/Context;

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Landroid/content/Context;->checkCallingOrSelfPermission(Ljava/lang/String;)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_0
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 25
    .line 26
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lvp/p0;->q:Lvp/n0;

    .line 30
    .line 31
    const-string v0, "Permission not granted"

    .line 32
    .line 33
    invoke-virtual {p0, p1, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const/4 p0, 0x0

    .line 37
    return p0
.end method
