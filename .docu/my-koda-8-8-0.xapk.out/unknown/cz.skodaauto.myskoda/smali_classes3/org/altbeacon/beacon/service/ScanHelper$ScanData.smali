.class Lorg/altbeacon/beacon/service/ScanHelper$ScanData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/service/ScanHelper;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "ScanData"
.end annotation


# instance fields
.field device:Landroid/bluetooth/BluetoothDevice;

.field final rssi:I

.field scanRecord:[B

.field final synthetic this$0:Lorg/altbeacon/beacon/service/ScanHelper;

.field timestampMs:J


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/ScanHelper;Landroid/bluetooth/BluetoothDevice;I[BJ)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->this$0:Lorg/altbeacon/beacon/service/ScanHelper;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->device:Landroid/bluetooth/BluetoothDevice;

    .line 7
    .line 8
    iput p3, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->rssi:I

    .line 9
    .line 10
    iput-object p4, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->scanRecord:[B

    .line 11
    .line 12
    iput-wide p5, p0, Lorg/altbeacon/beacon/service/ScanHelper$ScanData;->timestampMs:J

    .line 13
    .line 14
    return-void
.end method
