.class public final Lw/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lw/l;


# direct methods
.method public constructor <init>(ILjava/util/ArrayList;Lj0/h;Lu/h0;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lw/l;

    .line 5
    .line 6
    invoke-direct {v0, p1, p2, p3, p4}, Lw/l;-><init>(ILjava/util/ArrayList;Lj0/h;Lu/h0;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lw/m;->a:Lw/l;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lw/m;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    check-cast p1, Lw/m;

    .line 8
    .line 9
    iget-object p1, p1, Lw/m;->a:Lw/l;

    .line 10
    .line 11
    iget-object p0, p0, Lw/m;->a:Lw/l;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lw/l;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lw/m;->a:Lw/l;

    .line 2
    .line 3
    iget-object p0, p0, Lw/l;->a:Landroid/hardware/camera2/params/SessionConfiguration;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/hardware/camera2/params/SessionConfiguration;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method
