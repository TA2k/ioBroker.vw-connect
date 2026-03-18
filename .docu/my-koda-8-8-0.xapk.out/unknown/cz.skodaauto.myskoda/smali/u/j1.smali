.class public final Lu/j1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu/l;


# instance fields
.field public final synthetic a:Lh8/o;


# direct methods
.method public constructor <init>(Lh8/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu/j1;->a:Lh8/o;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Landroid/hardware/camera2/TotalCaptureResult;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lu/j1;->a:Lh8/o;

    .line 2
    .line 3
    iget-object p0, p0, Lh8/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lu/k1;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Lu/k1;->a(Landroid/hardware/camera2/TotalCaptureResult;)V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    return p0
.end method
