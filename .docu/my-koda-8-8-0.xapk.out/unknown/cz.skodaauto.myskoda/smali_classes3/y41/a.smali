.class public final Ly41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqm/a;


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Ljava/lang/Object;


# direct methods
.method public constructor <init>(ILd5/f;)V
    .locals 1

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p2, p0, Ly41/a;->a:Ljava/lang/Object;

    .line 6
    const-string p2, "top"

    if-eqz p1, :cond_1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_0

    .line 7
    const-string p1, "CCL"

    const-string v0, "horizontalAnchorIndexToAnchorName: Unknown horizontal index"

    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_0

    .line 8
    :cond_0
    const-string p2, "bottom"

    .line 9
    :cond_1
    :goto_0
    iput-object p2, p0, Ly41/a;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lmm/g;Lzl/h;)V
    .locals 0

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    iput-object p1, p0, Ly41/a;->a:Ljava/lang/Object;

    iput-object p2, p0, Ly41/a;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ly41/g;Lj51/i;Lb81/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p2, p0, Ly41/a;->a:Ljava/lang/Object;

    .line 3
    iput-object p3, p0, Ly41/a;->b:Ljava/lang/Object;

    return-void
.end method

.method public static c(Ly41/a;Lz4/g;FI)V
    .locals 1

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p3, :cond_0

    .line 5
    .line 6
    int-to-float p2, v0

    .line 7
    :cond_0
    int-to-float p3, v0

    .line 8
    invoke-virtual {p0, p1, p2, p3}, Ly41/a;->b(Lz4/g;FF)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public a(Lyl/j;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ly41/a;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lzl/h;

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Ly41/a;->a:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lmm/g;

    .line 10
    .line 11
    iget-object p0, p0, Lmm/g;->a:Landroid/content/Context;

    .line 12
    .line 13
    iget v1, v0, Lzl/h;->s:I

    .line 14
    .line 15
    invoke-static {p1, p0, v1}, Lzl/j;->f(Lyl/j;Landroid/content/Context;I)Li3/c;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    :goto_0
    new-instance p1, Lzl/e;

    .line 22
    .line 23
    invoke-direct {p1, p0}, Lzl/e;-><init>(Li3/c;)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, p1}, Lzl/h;->k(Lzl/h;Lzl/g;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public b(Lz4/g;FF)V
    .locals 3

    .line 1
    iget v0, p1, Lz4/g;->b:I

    .line 2
    .line 3
    const-string v1, "top"

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    if-eq v0, v2, :cond_0

    .line 9
    .line 10
    const-string v0, "CCL"

    .line 11
    .line 12
    const-string v2, "horizontalAnchorIndexToAnchorName: Unknown horizontal index"

    .line 13
    .line 14
    invoke-static {v0, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const-string v1, "bottom"

    .line 19
    .line 20
    :cond_1
    :goto_0
    new-instance v0, Ld5/a;

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    new-array v2, v2, [C

    .line 24
    .line 25
    invoke-direct {v0, v2}, Ld5/b;-><init>([C)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p1, Lz4/g;->a:Ljava/lang/Object;

    .line 29
    .line 30
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-static {p1}, Ld5/h;->o(Ljava/lang/String;)Ld5/h;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-virtual {v0, p1}, Ld5/b;->o(Ld5/c;)V

    .line 39
    .line 40
    .line 41
    invoke-static {v1}, Ld5/h;->o(Ljava/lang/String;)Ld5/h;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-virtual {v0, p1}, Ld5/b;->o(Ld5/c;)V

    .line 46
    .line 47
    .line 48
    new-instance p1, Ld5/e;

    .line 49
    .line 50
    invoke-direct {p1, p2}, Ld5/e;-><init>(F)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0, p1}, Ld5/b;->o(Ld5/c;)V

    .line 54
    .line 55
    .line 56
    new-instance p1, Ld5/e;

    .line 57
    .line 58
    invoke-direct {p1, p3}, Ld5/e;-><init>(F)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v0, p1}, Ld5/b;->o(Ld5/c;)V

    .line 62
    .line 63
    .line 64
    iget-object p1, p0, Ly41/a;->a:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p1, Ld5/f;

    .line 67
    .line 68
    iget-object p0, p0, Ly41/a;->b:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p0, Ljava/lang/String;

    .line 71
    .line 72
    invoke-virtual {p1, p0, v0}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 73
    .line 74
    .line 75
    return-void
.end method
