.class Lorg/altbeacon/beacon/BeaconTransmitter$1;
.super Landroid/bluetooth/le/AdvertiseCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/beacon/BeaconTransmitter;->getAdvertiseCallback()Landroid/bluetooth/le/AdvertiseCallback;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/BeaconTransmitter;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/BeaconTransmitter;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconTransmitter$1;->this$0:Lorg/altbeacon/beacon/BeaconTransmitter;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/bluetooth/le/AdvertiseCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onStartFailure(I)V
    .locals 3

    .line 1
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v1, "BeaconTransmitter"

    .line 10
    .line 11
    const-string v2, "Advertisement start failed, code: %s"

    .line 12
    .line 13
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconTransmitter$1;->this$0:Lorg/altbeacon/beacon/BeaconTransmitter;

    .line 17
    .line 18
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconTransmitter;->a(Lorg/altbeacon/beacon/BeaconTransmitter;)Landroid/bluetooth/le/AdvertiseCallback;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconTransmitter$1;->this$0:Lorg/altbeacon/beacon/BeaconTransmitter;

    .line 25
    .line 26
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconTransmitter;->a(Lorg/altbeacon/beacon/BeaconTransmitter;)Landroid/bluetooth/le/AdvertiseCallback;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {p0, p1}, Landroid/bluetooth/le/AdvertiseCallback;->onStartFailure(I)V

    .line 31
    .line 32
    .line 33
    :cond_0
    return-void
.end method

.method public onStartSuccess(Landroid/bluetooth/le/AdvertiseSettings;)V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v1, "BeaconTransmitter"

    .line 5
    .line 6
    const-string v2, "Advertisement start succeeded."

    .line 7
    .line 8
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconTransmitter$1;->this$0:Lorg/altbeacon/beacon/BeaconTransmitter;

    .line 12
    .line 13
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconTransmitter;->b(Lorg/altbeacon/beacon/BeaconTransmitter;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconTransmitter$1;->this$0:Lorg/altbeacon/beacon/BeaconTransmitter;

    .line 17
    .line 18
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconTransmitter;->a(Lorg/altbeacon/beacon/BeaconTransmitter;)Landroid/bluetooth/le/AdvertiseCallback;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconTransmitter$1;->this$0:Lorg/altbeacon/beacon/BeaconTransmitter;

    .line 25
    .line 26
    invoke-static {p0}, Lorg/altbeacon/beacon/BeaconTransmitter;->a(Lorg/altbeacon/beacon/BeaconTransmitter;)Landroid/bluetooth/le/AdvertiseCallback;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {p0, p1}, Landroid/bluetooth/le/AdvertiseCallback;->onStartSuccess(Landroid/bluetooth/le/AdvertiseSettings;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    return-void
.end method
