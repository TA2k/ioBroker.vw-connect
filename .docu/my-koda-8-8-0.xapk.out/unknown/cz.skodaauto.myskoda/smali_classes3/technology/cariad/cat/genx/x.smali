.class public final synthetic Ltechnology/cariad/cat/genx/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;


# direct methods
.method public synthetic constructor <init>(ZZZLtechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Ltechnology/cariad/cat/genx/x;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Ltechnology/cariad/cat/genx/x;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Ltechnology/cariad/cat/genx/x;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Ltechnology/cariad/cat/genx/x;->g:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/x;->f:Z

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/x;->g:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 4
    .line 5
    iget-boolean v2, p0, Ltechnology/cariad/cat/genx/x;->d:Z

    .line 6
    .line 7
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/x;->e:Z

    .line 8
    .line 9
    invoke-static {v2, p0, v0, v1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->d(ZZZLtechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method
