.class public final Lb0/p1;
.super Lb0/b0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Ljava/lang/Object;

.field public final h:Lb0/v0;

.field public final i:I

.field public final j:I


# direct methods
.method public constructor <init>(Lb0/a1;Landroid/util/Size;Lb0/v0;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lb0/b0;-><init>(Lb0/a1;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lb0/p1;->g:Ljava/lang/Object;

    .line 10
    .line 11
    if-nez p2, :cond_0

    .line 12
    .line 13
    iget-object p1, p0, Lb0/b0;->e:Lb0/a1;

    .line 14
    .line 15
    invoke-interface {p1}, Lb0/a1;->o()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    iput p1, p0, Lb0/p1;->i:I

    .line 20
    .line 21
    iget-object p1, p0, Lb0/b0;->e:Lb0/a1;

    .line 22
    .line 23
    invoke-interface {p1}, Lb0/a1;->m()I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    iput p1, p0, Lb0/p1;->j:I

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {p2}, Landroid/util/Size;->getWidth()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    iput p1, p0, Lb0/p1;->i:I

    .line 35
    .line 36
    invoke-virtual {p2}, Landroid/util/Size;->getHeight()I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    iput p1, p0, Lb0/p1;->j:I

    .line 41
    .line 42
    :goto_0
    iput-object p3, p0, Lb0/p1;->h:Lb0/v0;

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final i0()Lb0/v0;
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/p1;->h:Lb0/v0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()I
    .locals 0

    .line 1
    iget p0, p0, Lb0/p1;->j:I

    .line 2
    .line 3
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget p0, p0, Lb0/p1;->i:I

    .line 2
    .line 3
    return p0
.end method
