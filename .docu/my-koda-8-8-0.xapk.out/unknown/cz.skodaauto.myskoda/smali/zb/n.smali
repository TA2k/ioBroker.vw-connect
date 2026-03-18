.class public final Lzb/n;
.super Lw3/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx4/q;


# instance fields
.field public final l:Landroid/view/Window;

.field public m:Z

.field public final n:Ll2/j1;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/util/UUID;Landroid/view/Window;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lw3/a;-><init>(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lzb/n;->l:Landroid/view/Window;

    .line 5
    .line 6
    sget-object p1, Lzb/b;->d:Lt2/b;

    .line 7
    .line 8
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lzb/n;->n:Ll2/j1;

    .line 13
    .line 14
    new-instance p1, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string p3, "Dialog:"

    .line 17
    .line 18
    invoke-direct {p1, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const p2, 0x7f0a00e9

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, p2, p1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    const/4 p1, 0x0

    .line 35
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method private final getContent()Lay0/n;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/n;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lzb/n;->n:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lay0/n;

    .line 8
    .line 9
    return-object p0
.end method

.method private final setContent(Lay0/n;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/n;",
            ")V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lzb/n;->n:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x6c6ccd2b

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
    if-eqz v0, :cond_2

    .line 35
    .line 36
    const v0, 0x76abaa0c

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 40
    .line 41
    .line 42
    invoke-direct {p0}, Lzb/n;->getContent()Lay0/n;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-static {v4, v0, p1, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 47
    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 51
    .line 52
    .line 53
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-eqz p1, :cond_3

    .line 58
    .line 59
    new-instance v0, Lza0/j;

    .line 60
    .line 61
    const/4 v1, 0x2

    .line 62
    invoke-direct {v0, p0, p2, v1}, Lza0/j;-><init>(Ljava/lang/Object;II)V

    .line 63
    .line 64
    .line 65
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 66
    .line 67
    :cond_3
    return-void
.end method

.method public getShouldCreateCompositionOnAttachedToWindow()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lzb/n;->m:Z

    .line 2
    .line 3
    return p0
.end method

.method public getWindow()Landroid/view/Window;
    .locals 0

    .line 1
    iget-object p0, p0, Lzb/n;->l:Landroid/view/Window;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i(Ll2/x;Lay0/n;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lw3/a;->setParentCompositionContext(Ll2/x;)V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0, p2}, Lzb/n;->setContent(Lay0/n;)V

    .line 5
    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    iput-boolean p1, p0, Lzb/n;->m:Z

    .line 9
    .line 10
    invoke-virtual {p0}, Lw3/a;->c()V

    .line 11
    .line 12
    .line 13
    return-void
.end method
