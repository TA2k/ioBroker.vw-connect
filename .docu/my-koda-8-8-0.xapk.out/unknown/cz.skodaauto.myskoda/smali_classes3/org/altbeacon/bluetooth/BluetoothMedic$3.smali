.class Lorg/altbeacon/bluetooth/BluetoothMedic$3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/bluetooth/BluetoothMedic;->cycleBluetooth()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;


# direct methods
.method public constructor <init>(Lorg/altbeacon/bluetooth/BluetoothMedic;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$3;->this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public run()V
    .locals 3

    .line 1
    invoke-static {}, Lorg/altbeacon/bluetooth/BluetoothMedic;->e()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    new-array v1, v1, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string v2, "Turning Bluetooth back on."

    .line 9
    .line 10
    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$3;->this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 14
    .line 15
    invoke-static {v0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->a(Lorg/altbeacon/bluetooth/BluetoothMedic;)Landroid/bluetooth/BluetoothAdapter;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothMedic$3;->this$0:Lorg/altbeacon/bluetooth/BluetoothMedic;

    .line 22
    .line 23
    invoke-static {p0}, Lorg/altbeacon/bluetooth/BluetoothMedic;->a(Lorg/altbeacon/bluetooth/BluetoothMedic;)Landroid/bluetooth/BluetoothAdapter;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothAdapter;->enable()Z

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void
.end method
