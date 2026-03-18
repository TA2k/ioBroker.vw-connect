.class Lorg/altbeacon/bluetooth/BluetoothTestJob$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/bluetooth/BluetoothTestJob;->onStartJob(Landroid/app/job/JobParameters;)Z
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/bluetooth/BluetoothTestJob;

.field final synthetic val$params:Landroid/app/job/JobParameters;


# direct methods
.method public constructor <init>(Lorg/altbeacon/bluetooth/BluetoothTestJob;Landroid/app/job/JobParameters;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothTestJob;

    .line 2
    .line 3
    iput-object p2, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob$1;->val$params:Landroid/app/job/JobParameters;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public run()V
    .locals 6

    .line 1
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothTestJob;->a()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "Bluetooth Test Job running"

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    new-array v3, v2, [Ljava/lang/Object;

    .line 9
    .line 10
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob$1;->val$params:Landroid/app/job/JobParameters;

    .line 14
    .line 15
    invoke-virtual {v0}, Landroid/app/job/JobParameters;->getExtras()Landroid/os/PersistableBundle;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v1, "test_type"

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    const/4 v1, 0x1

    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothTestJob;->a()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    const-string v4, "No test specified.  Done with job."

    .line 33
    .line 34
    new-array v5, v2, [Ljava/lang/Object;

    .line 35
    .line 36
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    move v3, v1

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    move v3, v2

    .line 42
    :goto_0
    and-int/lit8 v4, v0, 0x1

    .line 43
    .line 44
    if-ne v4, v1, :cond_2

    .line 45
    .line 46
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothTestJob;->a()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    const-string v4, "Scan test specified."

    .line 51
    .line 52
    new-array v5, v2, [Ljava/lang/Object;

    .line 53
    .line 54
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothMedic;->getInstance()Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    iget-object v4, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothTestJob;

    .line 62
    .line 63
    invoke-virtual {v3, v4}, Lorg/altbeacon/bluetooth/BluetoothMedic;->runScanTest(Landroid/content/Context;)Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-nez v3, :cond_1

    .line 68
    .line 69
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothTestJob;->a()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    const-string v4, "scan test failed"

    .line 74
    .line 75
    new-array v5, v2, [Ljava/lang/Object;

    .line 76
    .line 77
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :cond_1
    move v3, v1

    .line 81
    :cond_2
    and-int/lit8 v4, v0, 0x2

    .line 82
    .line 83
    const/4 v5, 0x2

    .line 84
    if-ne v4, v5, :cond_4

    .line 85
    .line 86
    if-eqz v3, :cond_3

    .line 87
    .line 88
    const-wide/16 v3, 0x2710

    .line 89
    .line 90
    :try_start_0
    invoke-static {v3, v4}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 91
    .line 92
    .line 93
    :catch_0
    :cond_3
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothTestJob;->a()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    const-string v4, "Transmit test specified."

    .line 98
    .line 99
    new-array v5, v2, [Ljava/lang/Object;

    .line 100
    .line 101
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothMedic;->getInstance()Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    iget-object v4, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothTestJob;

    .line 109
    .line 110
    invoke-virtual {v3, v4}, Lorg/altbeacon/bluetooth/BluetoothMedic;->runTransmitterTest(Landroid/content/Context;)Z

    .line 111
    .line 112
    .line 113
    move-result v3

    .line 114
    if-nez v3, :cond_5

    .line 115
    .line 116
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothTestJob;->a()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v3

    .line 120
    const-string v4, "transmit test failed"

    .line 121
    .line 122
    new-array v5, v2, [Ljava/lang/Object;

    .line 123
    .line 124
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_4
    move v1, v3

    .line 129
    :cond_5
    :goto_1
    if-nez v1, :cond_6

    .line 130
    .line 131
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothTestJob;->a()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    const-string v3, "Unknown test type:"

    .line 136
    .line 137
    const-string v4, "  Exiting."

    .line 138
    .line 139
    invoke-static {v3, v0, v4}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    new-array v3, v2, [Ljava/lang/Object;

    .line 144
    .line 145
    invoke-static {v1, v0, v3}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_6
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob$1;->this$0:Lorg/altbeacon/bluetooth/BluetoothTestJob;

    .line 149
    .line 150
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothTestJob$1;->val$params:Landroid/app/job/JobParameters;

    .line 151
    .line 152
    invoke-virtual {v0, p0, v2}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    .line 153
    .line 154
    .line 155
    return-void
.end method
