.class Lorg/altbeacon/bluetooth/BluetoothMedic$2;
.super Landroid/bluetooth/le/AdvertiseCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/bluetooth/BluetoothMedic;->runTransmitterTest(Landroid/content/Context;)Z
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;

.field final synthetic val$advertiser:Landroid/bluetooth/le/BluetoothLeAdvertiser;


# direct methods
.method public constructor <init>(Lorg/altbeacon/bluetooth/BluetoothMedic;Landroid/bluetooth/le/BluetoothLeAdvertiser;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$2;->this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 2
    .line 3
    iput-object p2, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$2;->val$advertiser:Landroid/bluetooth/le/BluetoothLeAdvertiser;

    .line 4
    .line 5
    invoke-direct {p0}, Landroid/bluetooth/le/AdvertiseCallback;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public onStartFailure(I)V
    .locals 4

    .line 1
    invoke-super {p0, p1}, Landroid/bluetooth/le/AdvertiseCallback;->onStartFailure(I)V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothMedic;->e()Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    const/4 v1, 0x0

    .line 9
    new-array v2, v1, [Ljava/lang/Object;

    .line 10
    .line 11
    const-string v3, "Sending onStartFailure event"

    .line 12
    .line 13
    invoke-static {v0, v3, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$2;->this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 17
    .line 18
    const-string v2, "onStartFailed"

    .line 19
    .line 20
    invoke-virtual {v0, v2, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->processMedicAction(Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    const/4 v0, 0x4

    .line 24
    if-ne p1, v0, :cond_0

    .line 25
    .line 26
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$2;->this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 27
    .line 28
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 29
    .line 30
    invoke-static {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->c(Lorg/altbeacon/bluetooth/BluetoothMedic;Ljava/lang/Boolean;)V

    .line 31
    .line 32
    .line 33
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothMedic;->e()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const-string p1, "Transmitter test failed in a way we consider a test failure"

    .line 38
    .line 39
    new-array v0, v1, [Ljava/lang/Object;

    .line 40
    .line 41
    invoke-static {p0, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$2;->this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 46
    .line 47
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 48
    .line 49
    invoke-static {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->c(Lorg/altbeacon/bluetooth/BluetoothMedic;Ljava/lang/Boolean;)V

    .line 50
    .line 51
    .line 52
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothMedic;->e()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    const-string p1, "Transmitter test failed, but not in a way we consider a test failure"

    .line 57
    .line 58
    new-array v0, v1, [Ljava/lang/Object;

    .line 59
    .line 60
    invoke-static {p0, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    return-void
.end method

.method public onStartSuccess(Landroid/bluetooth/le/AdvertiseSettings;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroid/bluetooth/le/AdvertiseCallback;->onStartSuccess(Landroid/bluetooth/le/AdvertiseSettings;)V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothMedic;->e()Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    const/4 v0, 0x0

    .line 9
    new-array v0, v0, [Ljava/lang/Object;

    .line 10
    .line 11
    const-string v1, "Transmitter test succeeded"

    .line 12
    .line 13
    invoke-static {p1, v1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iget-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$2;->val$advertiser:Landroid/bluetooth/le/BluetoothLeAdvertiser;

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Landroid/bluetooth/le/BluetoothLeAdvertiser;->stopAdvertising(Landroid/bluetooth/le/AdvertiseCallback;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$2;->this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 22
    .line 23
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 24
    .line 25
    invoke-static {p0, p1}, Lorg/altbeacon/bluetooth/BluetoothMedic;->c(Lorg/altbeacon/bluetooth/BluetoothMedic;Ljava/lang/Boolean;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
