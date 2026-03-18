.class public final Lw4/k;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:Landroid/content/Context;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Ll2/r;

.field public final synthetic i:Lu2/g;

.field public final synthetic j:I

.field public final synthetic k:Landroid/view/View;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lay0/k;Ll2/r;Lu2/g;ILandroid/view/View;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lw4/k;->f:Landroid/content/Context;

    .line 2
    .line 3
    iput-object p2, p0, Lw4/k;->g:Lay0/k;

    .line 4
    .line 5
    iput-object p3, p0, Lw4/k;->h:Ll2/r;

    .line 6
    .line 7
    iput-object p4, p0, Lw4/k;->i:Lu2/g;

    .line 8
    .line 9
    iput p5, p0, Lw4/k;->j:I

    .line 10
    .line 11
    iput-object p6, p0, Lw4/k;->k:Landroid/view/View;

    .line 12
    .line 13
    const/4 p1, 0x0

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    new-instance v0, Lw4/o;

    .line 2
    .line 3
    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.node.Owner"

    .line 4
    .line 5
    iget-object v2, p0, Lw4/k;->k:Landroid/view/View;

    .line 6
    .line 7
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object v6, v2

    .line 11
    check-cast v6, Lv3/o1;

    .line 12
    .line 13
    iget-object v1, p0, Lw4/k;->f:Landroid/content/Context;

    .line 14
    .line 15
    iget-object v2, p0, Lw4/k;->g:Lay0/k;

    .line 16
    .line 17
    iget-object v3, p0, Lw4/k;->h:Ll2/r;

    .line 18
    .line 19
    iget-object v4, p0, Lw4/k;->i:Lu2/g;

    .line 20
    .line 21
    iget v5, p0, Lw4/k;->j:I

    .line 22
    .line 23
    invoke-direct/range {v0 .. v6}, Lw4/o;-><init>(Landroid/content/Context;Lay0/k;Ll2/r;Lu2/g;ILv3/o1;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Lw4/g;->getLayoutNode()Lv3/h0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method
