.class public final Lzb/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lp1/f;


# instance fields
.field public final a:F


# direct methods
.method public constructor <init>(F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lzb/e0;->a:F

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lo1/d0;I)I
    .locals 0

    .line 1
    iget p0, p0, Lzb/e0;->a:F

    .line 2
    .line 3
    iget-object p1, p1, Lo1/d0;->e:Lt3/p1;

    .line 4
    .line 5
    invoke-interface {p1, p0}, Lt4/c;->Q(F)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    sub-int/2addr p2, p0

    .line 10
    return p2
.end method
