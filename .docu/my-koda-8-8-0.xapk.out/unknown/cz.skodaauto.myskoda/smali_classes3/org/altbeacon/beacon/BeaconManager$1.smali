.class Lorg/altbeacon/beacon/BeaconManager$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/beacon/BeaconManager;->configureScanStrategyWhenConsumersUnbound(Ljava/util/List;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/BeaconManager;

.field final synthetic val$oldConsumers:Ljava/util/List;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/BeaconManager;Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/BeaconManager$1;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    iput-object p2, p0, Lorg/altbeacon/beacon/BeaconManager$1;->val$oldConsumers:Ljava/util/List;

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
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/BeaconManager$1;->this$0:Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    iget-object p0, p0, Lorg/altbeacon/beacon/BeaconManager$1;->val$oldConsumers:Ljava/util/List;

    .line 4
    .line 5
    invoke-static {v0, p0}, Lorg/altbeacon/beacon/BeaconManager;->j(Lorg/altbeacon/beacon/BeaconManager;Ljava/util/List;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
