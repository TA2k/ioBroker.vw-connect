.class public final Lkn/n0;
.super Lw3/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx4/q;


# instance fields
.field public final l:Landroid/view/Window;

.field public final m:Ll2/j1;

.field public n:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/view/Window;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lw3/a;-><init>(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lkn/n0;->l:Landroid/view/Window;

    .line 5
    .line 6
    sget-object p1, Lkn/g0;->a:Lt2/b;

    .line 7
    .line 8
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lkn/n0;->m:Ll2/j1;

    .line 13
    .line 14
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
    iget-object p0, p0, Lkn/n0;->m:Ll2/j1;

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
    iget-object p0, p0, Lkn/n0;->m:Ll2/j1;

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
    .locals 2

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x3fb5b459

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-direct {p0}, Lkn/n0;->getContent()Lay0/n;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-interface {v0, p1, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    if-eqz p1, :cond_0

    .line 26
    .line 27
    new-instance v0, Lb1/g;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    invoke-direct {v0, p0, p2, v1}, Lb1/g;-><init>(Lw3/a;II)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 34
    .line 35
    :cond_0
    return-void
.end method

.method public getShouldCreateCompositionOnAttachedToWindow()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkn/n0;->n:Z

    .line 2
    .line 3
    return p0
.end method

.method public getWindow()Landroid/view/Window;
    .locals 0

    .line 1
    iget-object p0, p0, Lkn/n0;->l:Landroid/view/Window;

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
    invoke-direct {p0, p2}, Lkn/n0;->setContent(Lay0/n;)V

    .line 5
    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    iput-boolean p1, p0, Lkn/n0;->n:Z

    .line 9
    .line 10
    invoke-virtual {p0}, Lw3/a;->c()V

    .line 11
    .line 12
    .line 13
    return-void
.end method
