.class public Lorg/altbeacon/beacon/startup/StartupBroadcastReceiver;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TAG:Ljava/lang/String; = "StartupBroadcastReceiver"


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
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 5

    .line 1
    const/4 p0, 0x0

    .line 2
    new-array v0, p0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v1, "StartupBroadcastReceiver"

    .line 5
    .line 6
    const-string v2, "onReceive called in startup broadcast receiver"

    .line 7
    .line 8
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v2, "android.intent.action.BOOT_COMPLETED"

    .line 24
    .line 25
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    const-string v0, "Android Beacon Library restarted via ACTION_BOOT_COMPLETED"

    .line 32
    .line 33
    new-array v2, p0, [Ljava/lang/Object;

    .line 34
    .line 35
    invoke-static {v1, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->foregroundServiceStartFailed()Z

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    if-eqz v2, :cond_0

    .line 51
    .line 52
    const-string v2, "Foreground service startup failure detected.  We will retry starting now that we have received a BOOT_COMPLETED action."

    .line 53
    .line 54
    new-array v3, p0, [Ljava/lang/Object;

    .line 55
    .line 56
    invoke-static {v1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->retryForegroundServiceScanning()V

    .line 60
    .line 61
    .line 62
    :cond_0
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->isAnyConsumerBound()Z

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    if-nez v2, :cond_2

    .line 75
    .line 76
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getScheduledScanJobsEnabled()Z

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    if-nez v2, :cond_2

    .line 81
    .line 82
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getIntentScanStrategyCoordinator()Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    if-eqz v2, :cond_1

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_1
    const-string p1, "No consumers are bound.  Ignoring broadcast receiver."

    .line 90
    .line 91
    new-array p0, p0, [Ljava/lang/Object;

    .line 92
    .line 93
    invoke-static {v1, p1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :cond_2
    :goto_0
    const-string v2, "android.bluetooth.le.extra.CALLBACK_TYPE"

    .line 98
    .line 99
    const/4 v3, -0x1

    .line 100
    invoke-virtual {p2, v2, v3}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    if-eq v2, v3, :cond_6

    .line 105
    .line 106
    const-string v4, "Passive background scan callback type: "

    .line 107
    .line 108
    invoke-static {v2, v4}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    new-array v4, p0, [Ljava/lang/Object;

    .line 113
    .line 114
    invoke-static {v1, v2, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    const-string v2, "got Android background scan via intent"

    .line 118
    .line 119
    new-array v4, p0, [Ljava/lang/Object;

    .line 120
    .line 121
    invoke-static {v1, v2, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    const-string v2, "android.bluetooth.le.extra.ERROR_CODE"

    .line 125
    .line 126
    invoke-virtual {p2, v2, v3}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    if-eq v2, v3, :cond_3

    .line 131
    .line 132
    const-string v3, "Passive background scan failed.  Code; "

    .line 133
    .line 134
    invoke-static {v2, v3}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    new-array p0, p0, [Ljava/lang/Object;

    .line 139
    .line 140
    invoke-static {v1, v2, p0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    :cond_3
    const-string p0, "android.bluetooth.le.extra.LIST_SCAN_RESULT"

    .line 144
    .line 145
    invoke-virtual {p2, p0}, Landroid/content/Intent;->getParcelableArrayListExtra(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getIntentScanStrategyCoordinator()Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 150
    .line 151
    .line 152
    move-result-object p2

    .line 153
    if-eqz p2, :cond_4

    .line 154
    .line 155
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getIntentScanStrategyCoordinator()Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    invoke-virtual {p1, p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->processScanResults(Ljava/util/ArrayList;)V

    .line 160
    .line 161
    .line 162
    return-void

    .line 163
    :cond_4
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getScheduledScanJobsEnabled()Z

    .line 164
    .line 165
    .line 166
    move-result p2

    .line 167
    if-eqz p2, :cond_5

    .line 168
    .line 169
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 170
    .line 171
    .line 172
    move-result-object p2

    .line 173
    invoke-virtual {p2, p1, p0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->scheduleAfterBackgroundWakeup(Landroid/content/Context;Ljava/util/List;)V

    .line 174
    .line 175
    .line 176
    :cond_5
    return-void

    .line 177
    :cond_6
    const-string p1, "wakeup"

    .line 178
    .line 179
    invoke-virtual {p2, p1, p0}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z

    .line 180
    .line 181
    .line 182
    move-result v0

    .line 183
    if-eqz v0, :cond_7

    .line 184
    .line 185
    const-string p1, "got wake up intent"

    .line 186
    .line 187
    new-array p0, p0, [Ljava/lang/Object;

    .line 188
    .line 189
    invoke-static {v1, p1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    return-void

    .line 193
    :cond_7
    invoke-virtual {p2, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    filled-new-array {p2, p0}, [Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    const-string p1, "Already started.  Ignoring intent: %s of type: %s"

    .line 202
    .line 203
    invoke-static {v1, p1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    return-void
.end method
