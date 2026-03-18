.class public final Lo40/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lln0/g;


# direct methods
.method public constructor <init>(Lln0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo40/b0;->a:Lln0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lon0/m;

    .line 5
    .line 6
    iget-object p0, p0, Lo40/b0;->a:Lln0/g;

    .line 7
    .line 8
    iput-object v1, p0, Lln0/g;->a:Lon0/m;

    .line 9
    .line 10
    return-object v0
.end method
