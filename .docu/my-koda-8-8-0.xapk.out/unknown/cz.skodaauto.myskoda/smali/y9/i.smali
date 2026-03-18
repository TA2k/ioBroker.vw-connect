.class public final synthetic Ly9/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic d:Ly9/j;

.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(Ly9/j;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly9/i;->d:Ly9/j;

    .line 5
    .line 6
    iput p2, p0, Ly9/i;->e:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 2

    .line 1
    iget-object p1, p0, Ly9/i;->d:Ly9/j;

    .line 2
    .line 3
    iget-object v0, p1, Ly9/j;->g:Ly9/r;

    .line 4
    .line 5
    iget v1, p1, Ly9/j;->f:I

    .line 6
    .line 7
    iget p0, p0, Ly9/i;->e:I

    .line 8
    .line 9
    if-eq p0, v1, :cond_0

    .line 10
    .line 11
    iget-object p1, p1, Ly9/j;->e:[F

    .line 12
    .line 13
    aget p0, p1, p0

    .line 14
    .line 15
    invoke-static {v0, p0}, Ly9/r;->b(Ly9/r;F)V

    .line 16
    .line 17
    .line 18
    :cond_0
    iget-object p0, v0, Ly9/r;->t:Landroid/widget/PopupWindow;

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->dismiss()V

    .line 21
    .line 22
    .line 23
    return-void
.end method
