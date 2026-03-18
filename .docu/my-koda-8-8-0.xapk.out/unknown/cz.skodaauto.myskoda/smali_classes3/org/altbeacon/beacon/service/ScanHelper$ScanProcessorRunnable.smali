.class Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/service/ScanHelper;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "ScanProcessorRunnable"
.end annotation


# instance fields
.field detectionTracker:Lorg/altbeacon/beacon/service/DetectionTracker;

.field nonBeaconLeScanCallback:Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;

.field scanData:Lorg/altbeacon/beacon/service/ScanHelper$ScanData;

.field final synthetic this$0:Lorg/altbeacon/beacon/service/ScanHelper;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/ScanHelper;Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;Lorg/altbeacon/beacon/service/ScanHelper$ScanData;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->this$0:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lorg/altbeacon/beacon/service/DetectionTracker;->getInstance()Lorg/altbeacon/beacon/service/DetectionTracker;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->detectionTracker:Lorg/altbeacon/beacon/service/DetectionTracker;

    .line 11
    .line 12
    iput-object p2, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->nonBeaconLeScanCallback:Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;

    .line 13
    .line 14
    iput-object p3, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->scanData:Lorg/altbeacon/beacon/service/ScanHelper$ScanData;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public run()V
    .locals 9

    .line 1
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanHelper;->f()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v2, "Processing packet"

    .line 13
    .line 14
    new-array v3, v1, [Ljava/lang/Object;

    .line 15
    .line 16
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->this$0:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 20
    .line 21
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->a(Lorg/altbeacon/beacon/service/ScanHelper;)Ljava/util/Set;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-lez v0, :cond_1

    .line 30
    .line 31
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanHelper;->f()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    new-instance v2, Ljava/lang/StringBuilder;

    .line 36
    .line 37
    const-string v3, "Decoding beacon. First parser layout: "

    .line 38
    .line 39
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-object v3, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->this$0:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 43
    .line 44
    invoke-static {v3}, Lorg/altbeacon/beacon/service/ScanHelper;->a(Lorg/altbeacon/beacon/service/ScanHelper;)Ljava/util/Set;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    check-cast v3, Lorg/altbeacon/beacon/BeaconParser;

    .line 57
    .line 58
    invoke-virtual {v3}, Lorg/altbeacon/beacon/BeaconParser;->getLayout()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    new-array v3, v1, [Ljava/lang/Object;

    .line 70
    .line 71
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_1
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanHelper;->f()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    const-string v2, "API No beacon parsers registered when decoding beacon"

    .line 80
    .line 81
    new-array v3, v1, [Ljava/lang/Object;

    .line 82
    .line 83
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    :goto_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->this$0:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 87
    .line 88
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanHelper;->a(Lorg/altbeacon/beacon/service/ScanHelper;)Ljava/util/Set;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    const/4 v2, 0x0

    .line 97
    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    if-eqz v3, :cond_3

    .line 102
    .line 103
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    move-object v3, v2

    .line 108
    check-cast v3, Lorg/altbeacon/beacon/BeaconParser;

    .line 109
    .line 110
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->scanData:Lorg/altbeacon/beacon/service/ScanHelper$ScanData;

    .line 111
    .line 112
    iget-object v4, v2, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->scanRecord:[B

    .line 113
    .line 114
    iget v5, v2, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->rssi:I

    .line 115
    .line 116
    iget-object v6, v2, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->device:Landroid/bluetooth/BluetoothDevice;

    .line 117
    .line 118
    iget-wide v7, v2, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->timestampMs:J

    .line 119
    .line 120
    invoke-virtual/range {v3 .. v8}, Lorg/altbeacon/beacon/BeaconParser;->fromScanData([BILandroid/bluetooth/BluetoothDevice;J)Lorg/altbeacon/beacon/Beacon;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    if-eqz v2, :cond_2

    .line 125
    .line 126
    :cond_3
    if-eqz v2, :cond_5

    .line 127
    .line 128
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    if-eqz v0, :cond_4

    .line 133
    .line 134
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanHelper;->f()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    new-instance v3, Ljava/lang/StringBuilder;

    .line 139
    .line 140
    const-string v4, "Beacon packet detected for: "

    .line 141
    .line 142
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    const-string v4, " with rssi "

    .line 149
    .line 150
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Beacon;->getRssi()I

    .line 154
    .line 155
    .line 156
    move-result v4

    .line 157
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    new-array v1, v1, [Ljava/lang/Object;

    .line 165
    .line 166
    invoke-static {v0, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    :cond_4
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->detectionTracker:Lorg/altbeacon/beacon/service/DetectionTracker;

    .line 170
    .line 171
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/DetectionTracker;->recordDetection()V

    .line 172
    .line 173
    .line 174
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->this$0:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 175
    .line 176
    invoke-static {p0, v2}, Lorg/altbeacon/beacon/service/ScanHelper;->d(Lorg/altbeacon/beacon/service/ScanHelper;Lorg/altbeacon/beacon/Beacon;)V

    .line 177
    .line 178
    .line 179
    return-void

    .line 180
    :cond_5
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->nonBeaconLeScanCallback:Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;

    .line 181
    .line 182
    if-eqz v0, :cond_6

    .line 183
    .line 184
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanProcessorRunnable;->scanData:Lorg/altbeacon/beacon/service/ScanHelper$ScanData;

    .line 185
    .line 186
    iget-object v1, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->device:Landroid/bluetooth/BluetoothDevice;

    .line 187
    .line 188
    iget v2, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->rssi:I

    .line 189
    .line 190
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->scanRecord:[B

    .line 191
    .line 192
    invoke-interface {v0, v1, v2, p0}, Lorg/altbeacon/beacon/service/scanner/NonBeaconLeScanCallback;->onNonBeaconLeScan(Landroid/bluetooth/BluetoothDevice;I[B)V

    .line 193
    .line 194
    .line 195
    :cond_6
    return-void
.end method
