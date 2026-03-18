.class public final Lzq/e;
.super Lwq/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final r:Landroid/graphics/RectF;


# direct methods
.method public constructor <init>(Lwq/m;Landroid/graphics/RectF;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lwq/g;-><init>(Lwq/m;)V

    .line 2
    iput-object p2, p0, Lzq/e;->r:Landroid/graphics/RectF;

    return-void
.end method

.method public constructor <init>(Lzq/e;)V
    .locals 0

    .line 3
    invoke-direct {p0, p1}, Lwq/g;-><init>(Lwq/g;)V

    .line 4
    iget-object p1, p1, Lzq/e;->r:Landroid/graphics/RectF;

    iput-object p1, p0, Lzq/e;->r:Landroid/graphics/RectF;

    return-void
.end method


# virtual methods
.method public final newDrawable()Landroid/graphics/drawable/Drawable;
    .locals 1

    .line 1
    new-instance v0, Lzq/f;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lwq/i;-><init>(Lwq/g;)V

    .line 4
    .line 5
    .line 6
    iput-object p0, v0, Lzq/f;->G:Lzq/e;

    .line 7
    .line 8
    invoke-virtual {v0}, Lwq/i;->invalidateSelf()V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
