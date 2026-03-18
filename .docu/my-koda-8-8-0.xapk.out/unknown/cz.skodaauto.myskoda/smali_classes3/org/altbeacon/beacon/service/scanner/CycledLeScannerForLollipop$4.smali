.class Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop$4;
.super Landroid/bluetooth/le/ScanCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;->getNewLeScanCallback()Landroid/bluetooth/le/ScanCallback;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop$4;->this$0:Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/bluetooth/le/ScanCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onBatchScanResults(Ljava/util/List;)V
    .locals 14
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Landroid/bluetooth/le/ScanResult;",
            ">;)V"
        }
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v1, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v2, "CycledLeScannerForLollipop"

    .line 5
    .line 6
    const-string v3, "got batch records"

    .line 7
    .line 8
    invoke-static {v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Landroid/bluetooth/le/ScanResult;

    .line 26
    .line 27
    iget-object v3, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop$4;->this$0:Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;

    .line 28
    .line 29
    iget-object v4, v3, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mCycledLeScanCallback:Lorg/altbeacon/beacon/service/scanner/CycledLeScanCallback;

    .line 30
    .line 31
    invoke-virtual {v1}, Landroid/bluetooth/le/ScanResult;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    invoke-virtual {v1}, Landroid/bluetooth/le/ScanResult;->getRssi()I

    .line 36
    .line 37
    .line 38
    move-result v6

    .line 39
    invoke-virtual {v1}, Landroid/bluetooth/le/ScanResult;->getScanRecord()Landroid/bluetooth/le/ScanRecord;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    invoke-virtual {v3}, Landroid/bluetooth/le/ScanRecord;->getBytes()[B

    .line 44
    .line 45
    .line 46
    move-result-object v7

    .line 47
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 48
    .line 49
    .line 50
    move-result-wide v8

    .line 51
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 52
    .line 53
    .line 54
    move-result-wide v10

    .line 55
    sub-long/2addr v8, v10

    .line 56
    invoke-virtual {v1}, Landroid/bluetooth/le/ScanResult;->getTimestampNanos()J

    .line 57
    .line 58
    .line 59
    move-result-wide v10

    .line 60
    const-wide/32 v12, 0xf4240

    .line 61
    .line 62
    .line 63
    div-long/2addr v10, v12

    .line 64
    add-long/2addr v8, v10

    .line 65
    invoke-interface/range {v4 .. v9}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanCallback;->onLeScan(Landroid/bluetooth/BluetoothDevice;I[BJ)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop$4;->this$0:Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;

    .line 70
    .line 71
    invoke-static {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;->b(Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;)J

    .line 72
    .line 73
    .line 74
    move-result-wide p0

    .line 75
    const-wide/16 v3, 0x0

    .line 76
    .line 77
    cmp-long p0, p0, v3

    .line 78
    .line 79
    if-lez p0, :cond_1

    .line 80
    .line 81
    const-string p0, "got a filtered batch scan result in the background."

    .line 82
    .line 83
    new-array p1, v0, [Ljava/lang/Object;

    .line 84
    .line 85
    invoke-static {v2, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_1
    return-void
.end method

.method public onScanFailed(I)V
    .locals 3

    .line 1
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothMedic;->getInstance()Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "onScanFailed"

    .line 6
    .line 7
    invoke-virtual {p0, v0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->processMedicAction(Ljava/lang/String;I)V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v0, 0x0

    .line 12
    const-string v1, "CycledLeScannerForLollipop"

    .line 13
    .line 14
    if-eq p1, p0, :cond_3

    .line 15
    .line 16
    const/4 p0, 0x2

    .line 17
    if-eq p1, p0, :cond_2

    .line 18
    .line 19
    const/4 p0, 0x3

    .line 20
    if-eq p1, p0, :cond_1

    .line 21
    .line 22
    const/4 p0, 0x4

    .line 23
    if-eq p1, p0, :cond_0

    .line 24
    .line 25
    const-string p0, "Scan failed with unknown error (errorCode="

    .line 26
    .line 27
    const-string v2, ")"

    .line 28
    .line 29
    invoke-static {p0, p1, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    new-array p1, v0, [Ljava/lang/Object;

    .line 34
    .line 35
    invoke-static {v1, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_0
    const-string p0, "Scan failed: power optimized scan feature is not supported"

    .line 40
    .line 41
    new-array p1, v0, [Ljava/lang/Object;

    .line 42
    .line 43
    invoke-static {v1, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    const-string p0, "Scan failed: internal error"

    .line 48
    .line 49
    new-array p1, v0, [Ljava/lang/Object;

    .line 50
    .line 51
    invoke-static {v1, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_2
    const-string p0, "Scan failed: app cannot be registered"

    .line 56
    .line 57
    new-array p1, v0, [Ljava/lang/Object;

    .line 58
    .line 59
    invoke-static {v1, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_3
    const-string p0, "Scan failed: a BLE scan with the same settings is already started by the app"

    .line 64
    .line 65
    new-array p1, v0, [Ljava/lang/Object;

    .line 66
    .line 67
    invoke-static {v1, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    return-void
.end method

.method public onScanResult(ILandroid/bluetooth/le/ScanResult;)V
    .locals 10

    .line 1
    invoke-static {}, Lorg/altbeacon/beacon/logging/LogManager;->isVerboseLoggingEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 v0, 0x0

    .line 6
    const-string v1, "CycledLeScannerForLollipop"

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    const-string p1, "got record"

    .line 11
    .line 12
    new-array v2, v0, [Ljava/lang/Object;

    .line 13
    .line 14
    invoke-static {v1, p1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p2}, Landroid/bluetooth/le/ScanResult;->getScanRecord()Landroid/bluetooth/le/ScanRecord;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p1}, Landroid/bluetooth/le/ScanRecord;->getServiceUuids()Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    if-eqz p1, :cond_0

    .line 26
    .line 27
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_0

    .line 36
    .line 37
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    check-cast v2, Landroid/os/ParcelUuid;

    .line 42
    .line 43
    new-instance v3, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    const-string v4, "with service uuid: "

    .line 46
    .line 47
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    new-array v3, v0, [Ljava/lang/Object;

    .line 58
    .line 59
    invoke-static {v1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop$4;->this$0:Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;

    .line 64
    .line 65
    iget-object v2, p1, Lorg/altbeacon/beacon/service/scanner/CycledLeScanner;->mCycledLeScanCallback:Lorg/altbeacon/beacon/service/scanner/CycledLeScanCallback;

    .line 66
    .line 67
    invoke-virtual {p2}, Landroid/bluetooth/le/ScanResult;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    invoke-virtual {p2}, Landroid/bluetooth/le/ScanResult;->getRssi()I

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    invoke-virtual {p2}, Landroid/bluetooth/le/ScanResult;->getScanRecord()Landroid/bluetooth/le/ScanRecord;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-virtual {p1}, Landroid/bluetooth/le/ScanRecord;->getBytes()[B

    .line 80
    .line 81
    .line 82
    move-result-object v5

    .line 83
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 84
    .line 85
    .line 86
    move-result-wide v6

    .line 87
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 88
    .line 89
    .line 90
    move-result-wide v8

    .line 91
    sub-long/2addr v6, v8

    .line 92
    invoke-virtual {p2}, Landroid/bluetooth/le/ScanResult;->getTimestampNanos()J

    .line 93
    .line 94
    .line 95
    move-result-wide p1

    .line 96
    const-wide/32 v8, 0xf4240

    .line 97
    .line 98
    .line 99
    div-long/2addr p1, v8

    .line 100
    add-long/2addr v6, p1

    .line 101
    invoke-interface/range {v2 .. v7}, Lorg/altbeacon/beacon/service/scanner/CycledLeScanCallback;->onLeScan(Landroid/bluetooth/BluetoothDevice;I[BJ)V

    .line 102
    .line 103
    .line 104
    iget-object p0, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop$4;->this$0:Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;

    .line 105
    .line 106
    invoke-static {p0}, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;->b(Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForLollipop;)J

    .line 107
    .line 108
    .line 109
    move-result-wide p0

    .line 110
    const-wide/16 v2, 0x0

    .line 111
    .line 112
    cmp-long p0, p0, v2

    .line 113
    .line 114
    if-lez p0, :cond_1

    .line 115
    .line 116
    const-string p0, "got a filtered scan result in the background."

    .line 117
    .line 118
    new-array p1, v0, [Ljava/lang/Object;

    .line 119
    .line 120
    invoke-static {v1, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    :cond_1
    return-void
.end method
