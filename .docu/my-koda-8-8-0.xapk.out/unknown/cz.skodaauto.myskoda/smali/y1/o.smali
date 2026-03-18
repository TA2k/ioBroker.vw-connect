.class public final Ly1/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ly1/o;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ly1/o;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ly1/o;->a:Ly1/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Landroid/graphics/drawable/Drawable;Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0xf5caf94

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x2

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    or-int/2addr v0, p3

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    const/4 v4, 0x1

    .line 24
    if-eq v2, v1, :cond_1

    .line 25
    .line 26
    move v1, v4

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v1, v3

    .line 29
    :goto_1
    and-int/2addr v0, v4

    .line 30
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_4

    .line 35
    .line 36
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 37
    .line 38
    sget v1, Lf1/f;->j:F

    .line 39
    .line 40
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    if-nez v1, :cond_2

    .line 53
    .line 54
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 55
    .line 56
    if-ne v2, v1, :cond_3

    .line 57
    .line 58
    :cond_2
    new-instance v2, Lw81/c;

    .line 59
    .line 60
    const/16 v1, 0x18

    .line 61
    .line 62
    invoke-direct {v2, p1, v1}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    :cond_3
    check-cast v2, Lay0/k;

    .line 69
    .line 70
    invoke-static {v0, v2}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    invoke-static {v0, p2, v3}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 75
    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 79
    .line 80
    .line 81
    :goto_2
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    if-eqz p2, :cond_5

    .line 86
    .line 87
    new-instance v0, Lx40/n;

    .line 88
    .line 89
    const/16 v1, 0xd

    .line 90
    .line 91
    invoke-direct {v0, p3, v1, p0, p1}, Lx40/n;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 95
    .line 96
    :cond_5
    return-void
.end method

.method public final b(Landroid/graphics/drawable/Icon;Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x7e274b59

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p3

    .line 19
    and-int/lit8 v1, v0, 0x13

    .line 20
    .line 21
    const/16 v2, 0x12

    .line 22
    .line 23
    const/4 v3, 0x1

    .line 24
    if-eq v1, v2, :cond_1

    .line 25
    .line 26
    move v1, v3

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/4 v1, 0x0

    .line 29
    :goto_1
    and-int/2addr v0, v3

    .line 30
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_5

    .line 35
    .line 36
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 37
    .line 38
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Landroid/content/Context;

    .line 43
    .line 44
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    invoke-virtual {p2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    or-int/2addr v1, v2

    .line 53
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    if-nez v1, :cond_2

    .line 58
    .line 59
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 60
    .line 61
    if-ne v2, v1, :cond_3

    .line 62
    .line 63
    :cond_2
    invoke-virtual {p1, v0}, Landroid/graphics/drawable/Icon;->loadDrawable(Landroid/content/Context;)Landroid/graphics/drawable/Drawable;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :cond_3
    check-cast v2, Landroid/graphics/drawable/Drawable;

    .line 71
    .line 72
    if-nez v2, :cond_4

    .line 73
    .line 74
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    if-eqz p2, :cond_6

    .line 79
    .line 80
    new-instance v0, Ly1/n;

    .line 81
    .line 82
    const/4 v1, 0x0

    .line 83
    invoke-direct {v0, p0, p1, p3, v1}, Ly1/n;-><init>(Ly1/o;Landroid/graphics/drawable/Icon;II)V

    .line 84
    .line 85
    .line 86
    :goto_2
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 87
    .line 88
    return-void

    .line 89
    :cond_4
    const/16 v0, 0x30

    .line 90
    .line 91
    invoke-virtual {p0, v2, p2, v0}, Ly1/o;->a(Landroid/graphics/drawable/Drawable;Ll2/o;I)V

    .line 92
    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 96
    .line 97
    .line 98
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    if-eqz p2, :cond_6

    .line 103
    .line 104
    new-instance v0, Ly1/n;

    .line 105
    .line 106
    const/4 v1, 0x1

    .line 107
    invoke-direct {v0, p0, p1, p3, v1}, Ly1/n;-><init>(Ly1/o;Landroid/graphics/drawable/Icon;II)V

    .line 108
    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_6
    return-void
.end method
