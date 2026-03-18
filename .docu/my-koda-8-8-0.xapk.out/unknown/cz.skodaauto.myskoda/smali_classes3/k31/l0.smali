.class public final Lk31/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr41/a;


# instance fields
.field public final a:Lf31/a;


# direct methods
.method public constructor <init>(Lf31/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk31/l0;->a:Lf31/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lay0/k;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lk31/l0;->a:Lf31/a;

    .line 2
    .line 3
    iget-object p0, p0, Lf31/a;->a:Lb31/a;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lb31/a;->d(Lay0/k;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lay0/k;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lk31/l0;->a(Lay0/k;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
