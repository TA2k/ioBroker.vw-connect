.class public final Lk31/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr41/a;


# instance fields
.field public final a:Lf31/h;


# direct methods
.method public constructor <init>(Lf31/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk31/k0;->a:Lf31/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lk31/j0;

    .line 5
    .line 6
    new-instance v2, Li40/e1;

    .line 7
    .line 8
    const/16 v3, 0x10

    .line 9
    .line 10
    invoke-direct {v2, v1, v3}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lk31/k0;->a:Lf31/h;

    .line 14
    .line 15
    iget-object p0, p0, Lf31/h;->a:Lb31/a;

    .line 16
    .line 17
    invoke-virtual {p0, v2}, Lb31/a;->d(Lay0/k;)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method
