.class public final synthetic Ltechnology/cariad/cat/genx/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/TransportType;

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/TransportType;Z)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Ltechnology/cariad/cat/genx/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/d;->e:Ltechnology/cariad/cat/genx/TransportType;

    iput-boolean p2, p0, Ltechnology/cariad/cat/genx/d;->f:Z

    return-void
.end method

.method public synthetic constructor <init>(ZLtechnology/cariad/cat/genx/TransportType;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Ltechnology/cariad/cat/genx/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Ltechnology/cariad/cat/genx/d;->f:Z

    iput-object p2, p0, Ltechnology/cariad/cat/genx/d;->e:Ltechnology/cariad/cat/genx/TransportType;

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/d;->e:Ltechnology/cariad/cat/genx/TransportType;

    .line 7
    .line 8
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/d;->f:Z

    .line 9
    .line 10
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->a(Ltechnology/cariad/cat/genx/TransportType;Z)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/d;->f:Z

    .line 16
    .line 17
    iget-object p0, p0, Ltechnology/cariad/cat/genx/d;->e:Ltechnology/cariad/cat/genx/TransportType;

    .line 18
    .line 19
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;->k(Ltechnology/cariad/cat/genx/TransportType;Z)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
