.class public final Lh2/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Le3/i;

.field public final b:Le3/k;

.field public final c:Le3/i;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Le3/k;

    .line 6
    .line 7
    new-instance v2, Landroid/graphics/PathMeasure;

    .line 8
    .line 9
    invoke-direct {v2}, Landroid/graphics/PathMeasure;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-direct {v1, v2}, Le3/k;-><init>(Landroid/graphics/PathMeasure;)V

    .line 13
    .line 14
    .line 15
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lh2/a1;->a:Le3/i;

    .line 23
    .line 24
    iput-object v1, p0, Lh2/a1;->b:Le3/k;

    .line 25
    .line 26
    iput-object v2, p0, Lh2/a1;->c:Le3/i;

    .line 27
    .line 28
    return-void
.end method
