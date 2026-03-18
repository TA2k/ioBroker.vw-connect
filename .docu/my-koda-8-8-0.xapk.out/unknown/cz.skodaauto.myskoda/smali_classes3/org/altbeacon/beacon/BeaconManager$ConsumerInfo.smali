.class Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/BeaconManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "ConsumerInfo"
.end annotation


# instance fields
.field public beaconServiceConnection:Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;

.field public isConnected:Z

.field final synthetic this$0:Lorg/altbeacon/beacon/BeaconManager;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    iput-boolean v0, p0, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;->isConnected:Z

    .line 8
    .line 9
    new-instance v1, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;

    .line 10
    .line 11
    invoke-direct {v1, p1, v0}, Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;-><init>(Lorg/altbeacon/beacon/BeaconManager;I)V

    .line 12
    .line 13
    .line 14
    iput-object v1, p0, Lorg/altbeacon/beacon/BeaconManager$ConsumerInfo;->beaconServiceConnection:Lorg/altbeacon/beacon/BeaconManager$BeaconServiceConnection;

    .line 15
    .line 16
    return-void
.end method
