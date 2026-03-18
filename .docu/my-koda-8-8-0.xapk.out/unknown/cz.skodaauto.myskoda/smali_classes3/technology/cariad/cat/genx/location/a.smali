.class public final synthetic Ltechnology/cariad/cat/genx/location/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Landroid/content/Context;

.field public final synthetic e:Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltechnology/cariad/cat/genx/location/a;->d:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Ltechnology/cariad/cat/genx/location/a;->e:Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/location/a;->d:Landroid/content/Context;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/location/a;->e:Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;

    .line 4
    .line 5
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1;->b(Landroid/content/Context;Ltechnology/cariad/cat/genx/location/Location$isLocationEnabled$1$receiver$1;)Llx0/b0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
