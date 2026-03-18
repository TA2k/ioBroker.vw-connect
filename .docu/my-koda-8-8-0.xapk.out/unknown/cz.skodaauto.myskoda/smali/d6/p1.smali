.class public Ld6/p1;
.super Ld6/o1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final r:Ld6/w1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    invoke-static {}, La8/m;->i()Landroid/view/WindowInsets;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-static {v1, v0}, Ld6/w1;->h(Landroid/view/View;Landroid/view/WindowInsets;)Ld6/w1;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Ld6/p1;->r:Ld6/w1;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Ld6/w1;Landroid/view/WindowInsets;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ld6/o1;-><init>(Ld6/w1;Landroid/view/WindowInsets;)V

    return-void
.end method

.method public constructor <init>(Ld6/w1;Ld6/p1;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1, p2}, Ld6/o1;-><init>(Ld6/w1;Ld6/o1;)V

    return-void
.end method


# virtual methods
.method public final d(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method

.method public g(I)Ls5/b;
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 2
    .line 3
    invoke-static {p1}, Ld6/u1;->a(I)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p0, p1}, La8/m;->w(Landroid/view/WindowInsets;I)Landroid/graphics/Insets;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Ls5/b;->c(Landroid/graphics/Insets;)Ls5/b;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public h(I)Ls5/b;
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 2
    .line 3
    invoke-static {p1}, Ld6/u1;->a(I)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p0, p1}, La8/m;->e(Landroid/view/WindowInsets;I)Landroid/graphics/Insets;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Ls5/b;->c(Landroid/graphics/Insets;)Ls5/b;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public q(I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 2
    .line 3
    invoke-static {p1}, Ld6/u1;->a(I)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p0, p1}, La8/m;->t(Landroid/view/WindowInsets;I)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method
