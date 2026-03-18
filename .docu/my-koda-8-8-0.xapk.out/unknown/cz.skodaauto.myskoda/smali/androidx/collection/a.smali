.class public final Landroidx/collection/a;
.super Ljava/util/AbstractSet;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:Landroidx/collection/f;


# direct methods
.method public constructor <init>(Landroidx/collection/f;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/collection/a;->d:Landroidx/collection/f;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/AbstractSet;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Landroidx/collection/d;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/collection/a;->d:Landroidx/collection/f;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Landroidx/collection/d;-><init>(Landroidx/collection/f;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final size()I
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/collection/a;->d:Landroidx/collection/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/collection/a1;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
