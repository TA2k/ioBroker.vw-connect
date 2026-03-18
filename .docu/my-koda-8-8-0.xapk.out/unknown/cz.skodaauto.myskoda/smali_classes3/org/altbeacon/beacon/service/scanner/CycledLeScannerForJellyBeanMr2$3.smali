.class Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;->postStopLeScan()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;

.field final synthetic val$bluetoothAdapter:Landroid/bluetooth/BluetoothAdapter;

.field final synthetic val$leScanCallback:Landroid/bluetooth/BluetoothAdapter$LeScanCallback;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;Landroid/bluetooth/BluetoothAdapter;Landroid/bluetooth/BluetoothAdapter$LeScanCallback;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$3;->this$0:Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2;

    .line 2
    .line 3
    iput-object p2, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$3;->val$bluetoothAdapter:Landroid/bluetooth/BluetoothAdapter;

    .line 4
    .line 5
    iput-object p3, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$3;->val$leScanCallback:Landroid/bluetooth/BluetoothAdapter$LeScanCallback;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public run()V
    .locals 3

    .line 1
    :try_start_0
    iget-object v0, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$3;->val$bluetoothAdapter:Landroid/bluetooth/BluetoothAdapter;

    .line 2
    .line 3
    iget-object p0, p0, Lorg/altbeacon/beacon/service/scanner/CycledLeScannerForJellyBeanMr2$3;->val$leScanCallback:Landroid/bluetooth/BluetoothAdapter$LeScanCallback;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Landroid/bluetooth/BluetoothAdapter;->stopLeScan(Landroid/bluetooth/BluetoothAdapter$LeScanCallback;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :catch_0
    move-exception p0

    .line 10
    const/4 v0, 0x0

    .line 11
    new-array v0, v0, [Ljava/lang/Object;

    .line 12
    .line 13
    const-string v1, "CycledLeScannerForJellyBeanMr2"

    .line 14
    .line 15
    const-string v2, "Internal Android exception in stopLeScan()"

    .line 16
    .line 17
    invoke-static {p0, v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
