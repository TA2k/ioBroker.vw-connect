.class public final Ltw/a;
.super Ltw/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:F


# direct methods
.method public constructor <init>(F)V
    .locals 1

    .line 1
    sget-object v0, Ltw/j;->a:Ltw/j;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Ltw/c;-><init>(Ltw/e;)V

    .line 4
    .line 5
    .line 6
    iput p1, p0, Ltw/a;->b:F

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(FF)F
    .locals 0

    .line 1
    iget p0, p0, Ltw/a;->b:F

    .line 2
    .line 3
    mul-float/2addr p0, p2

    .line 4
    return p0
.end method
