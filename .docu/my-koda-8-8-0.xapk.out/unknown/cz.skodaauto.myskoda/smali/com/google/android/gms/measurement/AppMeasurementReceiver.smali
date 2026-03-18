.class public final Lcom/google/android/gms/measurement/AppMeasurementReceiver;
.super Lm7/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public c:Lt1/j0;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/measurement/AppMeasurementReceiver;->c:Lt1/j0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lt1/j0;

    .line 6
    .line 7
    const/16 v1, 0xb

    .line 8
    .line 9
    invoke-direct {v0, p0, v1}, Lt1/j0;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lcom/google/android/gms/measurement/AppMeasurementReceiver;->c:Lt1/j0;

    .line 13
    .line 14
    :cond_0
    iget-object p0, p0, Lcom/google/android/gms/measurement/AppMeasurementReceiver;->c:Lt1/j0;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-static {p1, v0, v0}, Lvp/g1;->r(Landroid/content/Context;Lcom/google/android/gms/internal/measurement/u0;Ljava/lang/Long;)Lvp/g1;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 25
    .line 26
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 27
    .line 28
    .line 29
    if-nez p2, :cond_1

    .line 30
    .line 31
    iget-object p0, v0, Lvp/p0;->m:Lvp/n0;

    .line 32
    .line 33
    const-string p1, "Receiver called with null intent"

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    iget-object v1, v0, Lvp/p0;->r:Lvp/n0;

    .line 44
    .line 45
    const-string v2, "Local receiver got"

    .line 46
    .line 47
    invoke-virtual {v1, p2, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string v1, "com.google.android.gms.measurement.UPLOAD"

    .line 51
    .line 52
    invoke-virtual {v1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_4

    .line 57
    .line 58
    new-instance p2, Landroid/content/Intent;

    .line 59
    .line 60
    invoke-direct {p2}, Landroid/content/Intent;-><init>()V

    .line 61
    .line 62
    .line 63
    const-string v1, "com.google.android.gms.measurement.AppMeasurementService"

    .line 64
    .line 65
    invoke-virtual {p2, p1, v1}, Landroid/content/Intent;->setClassName(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    const-string v1, "com.google.android.gms.measurement.UPLOAD"

    .line 70
    .line 71
    invoke-virtual {p2, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 72
    .line 73
    .line 74
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 75
    .line 76
    const-string v1, "Starting wakeful intent."

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p0, Lcom/google/android/gms/measurement/AppMeasurementReceiver;

    .line 84
    .line 85
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    const-string p0, "androidx.core:wake:"

    .line 89
    .line 90
    sget-object v1, Lm7/a;->a:Landroid/util/SparseArray;

    .line 91
    .line 92
    monitor-enter v1

    .line 93
    :try_start_0
    sget v0, Lm7/a;->b:I

    .line 94
    .line 95
    add-int/lit8 v2, v0, 0x1

    .line 96
    .line 97
    sput v2, Lm7/a;->b:I

    .line 98
    .line 99
    const/4 v3, 0x1

    .line 100
    if-gtz v2, :cond_2

    .line 101
    .line 102
    sput v3, Lm7/a;->b:I

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :catchall_0
    move-exception p0

    .line 106
    goto :goto_1

    .line 107
    :cond_2
    :goto_0
    const-string v2, "androidx.contentpager.content.wakelockid"

    .line 108
    .line 109
    invoke-virtual {p2, v2, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 110
    .line 111
    .line 112
    invoke-virtual {p1, p2}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    if-nez p2, :cond_3

    .line 117
    .line 118
    monitor-exit v1

    .line 119
    return-void

    .line 120
    :cond_3
    const-string v2, "power"

    .line 121
    .line 122
    invoke-virtual {p1, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    check-cast p1, Landroid/os/PowerManager;

    .line 127
    .line 128
    new-instance v2, Ljava/lang/StringBuilder;

    .line 129
    .line 130
    invoke-direct {v2, p0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {p2}, Landroid/content/ComponentName;->flattenToShortString()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    invoke-virtual {p1, v3, p0}, Landroid/os/PowerManager;->newWakeLock(ILjava/lang/String;)Landroid/os/PowerManager$WakeLock;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    const/4 p1, 0x0

    .line 149
    invoke-virtual {p0, p1}, Landroid/os/PowerManager$WakeLock;->setReferenceCounted(Z)V

    .line 150
    .line 151
    .line 152
    const-wide/32 p1, 0xea60

    .line 153
    .line 154
    .line 155
    invoke-virtual {p0, p1, p2}, Landroid/os/PowerManager$WakeLock;->acquire(J)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v1, v0, p0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    monitor-exit v1

    .line 162
    return-void

    .line 163
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 164
    throw p0

    .line 165
    :cond_4
    const-string p0, "com.android.vending.INSTALL_REFERRER"

    .line 166
    .line 167
    invoke-virtual {p0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    if-eqz p0, :cond_5

    .line 172
    .line 173
    iget-object p0, v0, Lvp/p0;->m:Lvp/n0;

    .line 174
    .line 175
    const-string p1, "Install Referrer Broadcasts are deprecated"

    .line 176
    .line 177
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    :cond_5
    return-void
.end method
