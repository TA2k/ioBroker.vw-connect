.class public Ld6/h1;
.super Ld6/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ld6/g1;-><init>()V

    return-void
.end method

.method public constructor <init>(Ld6/w1;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Ld6/g1;-><init>(Ld6/w1;)V

    return-void
.end method


# virtual methods
.method public c(ILs5/b;)V
    .locals 0

    .line 1
    invoke-static {p1}, Ld6/u1;->a(I)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-virtual {p2}, Ls5/b;->d()Landroid/graphics/Insets;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    iget-object p0, p0, Ld6/g1;->c:Landroid/view/WindowInsets$Builder;

    .line 10
    .line 11
    invoke-static {p0, p1, p2}, La8/m;->p(Landroid/view/WindowInsets$Builder;ILandroid/graphics/Insets;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method
