.class public final Ld6/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnApplyWindowInsetsListener;


# instance fields
.field public a:Ld6/w1;

.field public final synthetic b:Landroid/view/View;

.field public final synthetic c:Ld6/s;


# direct methods
.method public constructor <init>(Landroid/view/View;Ld6/s;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ld6/j0;->b:Landroid/view/View;

    .line 2
    .line 3
    iput-object p2, p0, Ld6/j0;->c:Ld6/s;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput-object p1, p0, Ld6/j0;->a:Ld6/w1;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public onApplyWindowInsets(Landroid/view/View;Landroid/view/WindowInsets;)Landroid/view/WindowInsets;
    .locals 5

    .line 1
    invoke-static {p1, p2}, Ld6/w1;->h(Landroid/view/View;Landroid/view/WindowInsets;)Ld6/w1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 6
    .line 7
    iget-object v2, p0, Ld6/j0;->c:Ld6/s;

    .line 8
    .line 9
    const/16 v3, 0x1e

    .line 10
    .line 11
    if-ge v1, v3, :cond_0

    .line 12
    .line 13
    iget-object v4, p0, Ld6/j0;->b:Landroid/view/View;

    .line 14
    .line 15
    invoke-static {p2, v4}, Ld6/k0;->a(Landroid/view/WindowInsets;Landroid/view/View;)V

    .line 16
    .line 17
    .line 18
    iget-object p2, p0, Ld6/j0;->a:Ld6/w1;

    .line 19
    .line 20
    invoke-virtual {v0, p2}, Ld6/w1;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    if-eqz p2, :cond_0

    .line 25
    .line 26
    invoke-interface {v2, p1, v0}, Ld6/s;->onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {p0}, Ld6/w1;->g()Landroid/view/WindowInsets;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :cond_0
    iput-object v0, p0, Ld6/j0;->a:Ld6/w1;

    .line 36
    .line 37
    invoke-interface {v2, p1, v0}, Ld6/s;->onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    if-lt v1, v3, :cond_1

    .line 42
    .line 43
    invoke-virtual {p0}, Ld6/w1;->g()Landroid/view/WindowInsets;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :cond_1
    sget-object p2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 49
    .line 50
    invoke-static {p1}, Ld6/i0;->c(Landroid/view/View;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Ld6/w1;->g()Landroid/view/WindowInsets;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method
