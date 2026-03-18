.class public final Ly9/m;
.super Lka/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:[Ljava/lang/String;

.field public final e:[Ljava/lang/String;

.field public final f:[Landroid/graphics/drawable/Drawable;

.field public final synthetic g:Ly9/r;


# direct methods
.method public constructor <init>(Ly9/r;[Ljava/lang/String;[Landroid/graphics/drawable/Drawable;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ly9/m;->g:Ly9/r;

    .line 2
    .line 3
    invoke-direct {p0}, Lka/y;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Ly9/m;->d:[Ljava/lang/String;

    .line 7
    .line 8
    array-length p1, p2

    .line 9
    new-array p1, p1, [Ljava/lang/String;

    .line 10
    .line 11
    iput-object p1, p0, Ly9/m;->e:[Ljava/lang/String;

    .line 12
    .line 13
    iput-object p3, p0, Ly9/m;->f:[Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Ly9/m;->d:[Ljava/lang/String;

    .line 2
    .line 3
    array-length p0, p0

    .line 4
    return p0
.end method

.method public final b(I)J
    .locals 0

    .line 1
    int-to-long p0, p1

    .line 2
    return-wide p0
.end method

.method public final c(Lka/v0;I)V
    .locals 4

    .line 1
    check-cast p1, Ly9/l;

    .line 2
    .line 3
    iget-object v0, p1, Lka/v0;->a:Landroid/view/View;

    .line 4
    .line 5
    invoke-virtual {p0, p2}, Ly9/m;->e(I)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    new-instance v1, Lka/g0;

    .line 12
    .line 13
    const/4 v2, -0x1

    .line 14
    const/4 v3, -0x2

    .line 15
    invoke-direct {v1, v2, v3}, Lka/g0;-><init>(II)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v1}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lka/g0;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    invoke-direct {v1, v2, v2}, Lka/g0;-><init>(II)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, v1}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v0, p1, Ly9/l;->u:Landroid/widget/TextView;

    .line 32
    .line 33
    iget-object v1, p1, Ly9/l;->w:Landroid/widget/ImageView;

    .line 34
    .line 35
    iget-object p1, p1, Ly9/l;->v:Landroid/widget/TextView;

    .line 36
    .line 37
    iget-object v2, p0, Ly9/m;->d:[Ljava/lang/String;

    .line 38
    .line 39
    aget-object v2, v2, p2

    .line 40
    .line 41
    invoke-virtual {v0, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 42
    .line 43
    .line 44
    iget-object v0, p0, Ly9/m;->e:[Ljava/lang/String;

    .line 45
    .line 46
    aget-object v0, v0, p2

    .line 47
    .line 48
    const/16 v2, 0x8

    .line 49
    .line 50
    if-nez v0, :cond_1

    .line 51
    .line 52
    invoke-virtual {p1, v2}, Landroid/view/View;->setVisibility(I)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    invoke-virtual {p1, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 57
    .line 58
    .line 59
    :goto_1
    iget-object p0, p0, Ly9/m;->f:[Landroid/graphics/drawable/Drawable;

    .line 60
    .line 61
    aget-object p0, p0, p2

    .line 62
    .line 63
    if-nez p0, :cond_2

    .line 64
    .line 65
    invoke-virtual {v1, v2}, Landroid/widget/ImageView;->setVisibility(I)V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :cond_2
    invoke-virtual {v1, p0}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public final d(Landroid/view/ViewGroup;)Lka/v0;
    .locals 3

    .line 1
    iget-object p0, p0, Ly9/m;->g:Ly9/r;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const v1, 0x7f0d015b

    .line 12
    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-virtual {v0, v1, p1, v2}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    new-instance v0, Ly9/l;

    .line 20
    .line 21
    invoke-direct {v0, p0, p1}, Ly9/l;-><init>(Ly9/r;Landroid/view/View;)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public final e(I)Z
    .locals 3

    .line 1
    iget-object p0, p0, Ly9/m;->g:Ly9/r;

    .line 2
    .line 3
    iget-object v0, p0, Ly9/r;->B1:Lt7/l0;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    if-eqz p1, :cond_3

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    if-eq p1, v2, :cond_1

    .line 13
    .line 14
    return v2

    .line 15
    :cond_1
    const/16 p1, 0x1e

    .line 16
    .line 17
    check-cast v0, Lap0/o;

    .line 18
    .line 19
    invoke-virtual {v0, p1}, Lap0/o;->I(I)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_2

    .line 24
    .line 25
    iget-object p0, p0, Ly9/r;->B1:Lt7/l0;

    .line 26
    .line 27
    const/16 p1, 0x1d

    .line 28
    .line 29
    check-cast p0, Lap0/o;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lap0/o;->I(I)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-eqz p0, :cond_2

    .line 36
    .line 37
    return v2

    .line 38
    :cond_2
    return v1

    .line 39
    :cond_3
    const/16 p0, 0xd

    .line 40
    .line 41
    check-cast v0, Lap0/o;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lap0/o;->I(I)Z

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    return p0
.end method
