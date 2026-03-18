.class Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/bluetooth/BluetoothCrashResolver;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;


# direct methods
.method public constructor <init>(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 4

    .line 1
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const-string v0, "android.bluetooth.adapter.action.DISCOVERY_FINISHED"

    .line 6
    .line 7
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x0

    .line 12
    const-string v2, "BluetoothCrashResolver"

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 17
    .line 18
    invoke-static {v0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->c(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const-string v0, "Bluetooth discovery finished"

    .line 25
    .line 26
    new-array v3, v1, [Ljava/lang/Object;

    .line 27
    .line 28
    invoke-static {v2, v0, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 32
    .line 33
    invoke-static {v0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->g(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const-string v0, "Bluetooth discovery finished (external)"

    .line 38
    .line 39
    new-array v3, v1, [Ljava/lang/Object;

    .line 40
    .line 41
    invoke-static {v2, v0, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    :cond_1
    :goto_0
    const-string v0, "android.bluetooth.adapter.action.DISCOVERY_STARTED"

    .line 45
    .line 46
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-eqz v0, :cond_3

    .line 51
    .line 52
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 53
    .line 54
    invoke-static {v0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->c(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_2

    .line 59
    .line 60
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 61
    .line 62
    invoke-static {v0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->d(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)V

    .line 63
    .line 64
    .line 65
    const-string v0, "Bluetooth discovery started"

    .line 66
    .line 67
    new-array v3, v1, [Ljava/lang/Object;

    .line 68
    .line 69
    invoke-static {v2, v0, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_2
    const-string v0, "Bluetooth discovery started (external)"

    .line 74
    .line 75
    new-array v3, v1, [Ljava/lang/Object;

    .line 76
    .line 77
    invoke-static {v2, v0, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :cond_3
    :goto_1
    const-string v0, "android.bluetooth.adapter.action.STATE_CHANGED"

    .line 81
    .line 82
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    if-eqz p1, :cond_5

    .line 87
    .line 88
    const-string p1, "android.bluetooth.adapter.extra.STATE"

    .line 89
    .line 90
    const/high16 v0, -0x80000000

    .line 91
    .line 92
    invoke-virtual {p2, p1, v0}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 93
    .line 94
    .line 95
    move-result p1

    .line 96
    if-eq p1, v0, :cond_4

    .line 97
    .line 98
    packed-switch p1, :pswitch_data_0

    .line 99
    .line 100
    .line 101
    goto :goto_2

    .line 102
    :pswitch_0
    const-string p1, "Bluetooth state is ON"

    .line 103
    .line 104
    new-array p2, v1, [Ljava/lang/Object;

    .line 105
    .line 106
    invoke-static {v2, p1, p2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    iget-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 110
    .line 111
    invoke-static {p1}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->b(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)J

    .line 112
    .line 113
    .line 114
    move-result-wide p1

    .line 115
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 116
    .line 117
    invoke-static {v0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->a(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)J

    .line 118
    .line 119
    .line 120
    move-result-wide v0

    .line 121
    sub-long/2addr p1, v0

    .line 122
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    const-string p2, "Bluetooth was turned off for %s milliseconds"

    .line 131
    .line 132
    invoke-static {v2, p2, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    iget-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 136
    .line 137
    invoke-static {p1}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->b(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)J

    .line 138
    .line 139
    .line 140
    move-result-wide p1

    .line 141
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 142
    .line 143
    invoke-static {v0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->a(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)J

    .line 144
    .line 145
    .line 146
    move-result-wide v0

    .line 147
    sub-long/2addr p1, v0

    .line 148
    const-wide/16 v0, 0x258

    .line 149
    .line 150
    cmp-long p1, p1, v0

    .line 151
    .line 152
    if-gez p1, :cond_5

    .line 153
    .line 154
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 155
    .line 156
    invoke-virtual {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->crashDetected()V

    .line 157
    .line 158
    .line 159
    return-void

    .line 160
    :pswitch_1
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 161
    .line 162
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 163
    .line 164
    .line 165
    move-result-wide p1

    .line 166
    invoke-static {p0, p1, p2}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->f(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;J)V

    .line 167
    .line 168
    .line 169
    const-string p0, "Bluetooth state is TURNING_ON"

    .line 170
    .line 171
    new-array p1, v1, [Ljava/lang/Object;

    .line 172
    .line 173
    invoke-static {v2, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    return-void

    .line 177
    :pswitch_2
    const-string p1, "Bluetooth state is OFF"

    .line 178
    .line 179
    new-array p2, v1, [Ljava/lang/Object;

    .line 180
    .line 181
    invoke-static {v2, p1, p2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothCrashResolver;

    .line 185
    .line 186
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 187
    .line 188
    .line 189
    move-result-wide p1

    .line 190
    invoke-static {p0, p1, p2}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->e(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;J)V

    .line 191
    .line 192
    .line 193
    return-void

    .line 194
    :cond_4
    const-string p0, "Bluetooth state is ERROR"

    .line 195
    .line 196
    new-array p1, v1, [Ljava/lang/Object;

    .line 197
    .line 198
    invoke-static {v2, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    :cond_5
    :goto_2
    return-void

    .line 202
    nop

    .line 203
    :pswitch_data_0
    .packed-switch 0xa
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
