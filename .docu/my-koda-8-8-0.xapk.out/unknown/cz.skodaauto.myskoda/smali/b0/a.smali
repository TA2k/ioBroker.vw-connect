.class public final Lb0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/a1;


# instance fields
.field public final d:Landroid/media/Image;

.field public final e:[Lbu/c;

.field public final f:Lb0/f;


# direct methods
.method public constructor <init>(Landroid/media/Image;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb0/a;->d:Landroid/media/Image;

    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/media/Image;->getPlanes()[Landroid/media/Image$Plane;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    array-length v2, v0

    .line 14
    new-array v2, v2, [Lbu/c;

    .line 15
    .line 16
    iput-object v2, p0, Lb0/a;->e:[Lbu/c;

    .line 17
    .line 18
    :goto_0
    array-length v2, v0

    .line 19
    if-ge v1, v2, :cond_1

    .line 20
    .line 21
    iget-object v2, p0, Lb0/a;->e:[Lbu/c;

    .line 22
    .line 23
    new-instance v3, Lbu/c;

    .line 24
    .line 25
    aget-object v4, v0, v1

    .line 26
    .line 27
    const/4 v5, 0x4

    .line 28
    invoke-direct {v3, v4, v5}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 29
    .line 30
    .line 31
    aput-object v3, v2, v1

    .line 32
    .line 33
    add-int/lit8 v1, v1, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    new-array v0, v1, [Lbu/c;

    .line 37
    .line 38
    iput-object v0, p0, Lb0/a;->e:[Lbu/c;

    .line 39
    .line 40
    :cond_1
    sget-object v2, Lh0/j2;->b:Lh0/j2;

    .line 41
    .line 42
    invoke-virtual {p1}, Landroid/media/Image;->getTimestamp()J

    .line 43
    .line 44
    .line 45
    move-result-wide v3

    .line 46
    new-instance v6, Landroid/graphics/Matrix;

    .line 47
    .line 48
    invoke-direct {v6}, Landroid/graphics/Matrix;-><init>()V

    .line 49
    .line 50
    .line 51
    new-instance v1, Lb0/f;

    .line 52
    .line 53
    const/4 v5, 0x0

    .line 54
    const/4 v7, 0x0

    .line 55
    invoke-direct/range {v1 .. v7}, Lb0/f;-><init>(Lh0/j2;JILandroid/graphics/Matrix;I)V

    .line 56
    .line 57
    .line 58
    iput-object v1, p0, Lb0/a;->f:Lb0/f;

    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final R()[Lb0/z0;
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/a;->e:[Lbu/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/a;->d:Landroid/media/Image;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/media/Image;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final getFormat()I
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/a;->d:Landroid/media/Image;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/media/Image;->getFormat()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final i0()Lb0/v0;
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/a;->f:Lb0/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()I
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/a;->d:Landroid/media/Image;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/media/Image;->getHeight()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/a;->d:Landroid/media/Image;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/media/Image;->getWidth()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final r()Landroid/media/Image;
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/a;->d:Landroid/media/Image;

    .line 2
    .line 3
    return-object p0
.end method
