.class Lorg/altbeacon/beacon/service/scanner/ScanFilterUtils$ScanFilterData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/service/scanner/ScanFilterUtils;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "ScanFilterData"
.end annotation


# instance fields
.field public filter:[B

.field public manufacturer:I

.field public mask:[B

.field public serviceUuid:Ljava/lang/Long;

.field public serviceUuid128Bit:[B

.field final synthetic this$0:Lorg/altbeacon/beacon/service/scanner/ScanFilterUtils;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/scanner/ScanFilterUtils;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/scanner/ScanFilterUtils$ScanFilterData;->this$0:Lorg/altbeacon/beacon/service/scanner/ScanFilterUtils;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput-object p1, p0, Lorg/altbeacon/beacon/service/scanner/ScanFilterUtils$ScanFilterData;->serviceUuid:Ljava/lang/Long;

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    new-array p1, p1, [B

    .line 11
    .line 12
    iput-object p1, p0, Lorg/altbeacon/beacon/service/scanner/ScanFilterUtils$ScanFilterData;->serviceUuid128Bit:[B

    .line 13
    .line 14
    return-void
.end method
