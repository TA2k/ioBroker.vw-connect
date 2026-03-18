.class public Lorg/altbeacon/beacon/service/BeaconService$BeaconBinder;
.super Landroid/os/Binder;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/service/BeaconService;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "BeaconBinder"
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/service/BeaconService;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/BeaconService;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/BeaconService$BeaconBinder;->this$0:Lorg/altbeacon/beacon/service/BeaconService;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public getService()Lorg/altbeacon/beacon/service/BeaconService;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v1, "BeaconService"

    .line 5
    .line 6
    const-string v2, "getService of BeaconBinder called"

    .line 7
    .line 8
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lorg/altbeacon/beacon/service/BeaconService$BeaconBinder;->this$0:Lorg/altbeacon/beacon/service/BeaconService;

    .line 12
    .line 13
    return-object p0
.end method
