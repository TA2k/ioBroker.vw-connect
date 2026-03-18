.class public final Lw3/g1;
.super Lw3/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final l:Ll2/j1;

.field public m:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lw3/a;-><init>(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Lw3/g1;->l:Ll2/j1;

    .line 10
    .line 11
    return-void
.end method

.method public static synthetic getShouldCreateCompositionOnAttachedToWindow$annotations()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a(Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x190bf45a

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    or-int/2addr v0, p2

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    const/4 v3, 0x1

    .line 23
    const/4 v4, 0x0

    .line 24
    if-eq v2, v1, :cond_1

    .line 25
    .line 26
    move v1, v3

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v1, v4

    .line 29
    :goto_1
    and-int/2addr v0, v3

    .line 30
    invoke-virtual {p1, v0, v1}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_3

    .line 35
    .line 36
    iget-object v0, p0, Lw3/g1;->l:Ll2/j1;

    .line 37
    .line 38
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Lay0/n;

    .line 43
    .line 44
    if-nez v0, :cond_2

    .line 45
    .line 46
    const v0, -0x49d691a1

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 50
    .line 51
    .line 52
    :goto_2
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 53
    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_2
    const v1, 0x5e04de2

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1, v1}, Ll2/t;->Y(I)V

    .line 60
    .line 61
    .line 62
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-interface {v0, p1, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    :goto_3
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-eqz p1, :cond_4

    .line 78
    .line 79
    new-instance v0, Lb1/g;

    .line 80
    .line 81
    const/4 v1, 0x4

    .line 82
    invoke-direct {v0, p0, p2, v1}, Lb1/g;-><init>(Lw3/a;II)V

    .line 83
    .line 84
    .line 85
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 86
    .line 87
    :cond_4
    return-void
.end method

.method public getAccessibilityClassName()Ljava/lang/CharSequence;
    .locals 0

    .line 1
    const-class p0, Lw3/g1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getShouldCreateCompositionOnAttachedToWindow()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lw3/g1;->m:Z

    .line 2
    .line 3
    return p0
.end method

.method public final setContent(Lay0/n;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/n;",
            ")V"
        }
    .end annotation

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lw3/g1;->m:Z

    .line 3
    .line 4
    iget-object v0, p0, Lw3/g1;->l:Ll2/j1;

    .line 5
    .line 6
    invoke-virtual {v0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Lw3/a;->c()V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method
