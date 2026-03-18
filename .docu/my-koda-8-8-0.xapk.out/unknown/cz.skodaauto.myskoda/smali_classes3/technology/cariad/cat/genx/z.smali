.class public final synthetic Ltechnology/cariad/cat/genx/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Ltechnology/cariad/cat/genx/protocol/Priority;

.field public final synthetic f:Z

.field public final synthetic g:[B

.field public final synthetic h:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;


# direct methods
.method public synthetic constructor <init>(JLtechnology/cariad/cat/genx/protocol/Priority;Z[BLtechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Ltechnology/cariad/cat/genx/z;->d:J

    .line 5
    .line 6
    iput-object p3, p0, Ltechnology/cariad/cat/genx/z;->e:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 7
    .line 8
    iput-boolean p4, p0, Ltechnology/cariad/cat/genx/z;->f:Z

    .line 9
    .line 10
    iput-object p5, p0, Ltechnology/cariad/cat/genx/z;->g:[B

    .line 11
    .line 12
    iput-object p6, p0, Ltechnology/cariad/cat/genx/z;->h:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v4, p0, Ltechnology/cariad/cat/genx/z;->g:[B

    .line 2
    .line 3
    iget-object v5, p0, Ltechnology/cariad/cat/genx/z;->h:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 4
    .line 5
    iget-wide v0, p0, Ltechnology/cariad/cat/genx/z;->d:J

    .line 6
    .line 7
    iget-object v2, p0, Ltechnology/cariad/cat/genx/z;->e:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 8
    .line 9
    iget-boolean v3, p0, Ltechnology/cariad/cat/genx/z;->f:Z

    .line 10
    .line 11
    invoke-static/range {v0 .. v5}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->S0(JLtechnology/cariad/cat/genx/protocol/Priority;Z[BLtechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
