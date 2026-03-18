.class public final Ly9/l;
.super Lka/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final u:Landroid/widget/TextView;

.field public final v:Landroid/widget/TextView;

.field public final w:Landroid/widget/ImageView;

.field public final synthetic x:Ly9/r;


# direct methods
.method public constructor <init>(Ly9/r;Landroid/view/View;)V
    .locals 1

    .line 1
    iput-object p1, p0, Ly9/l;->x:Ly9/r;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lka/v0;-><init>(Landroid/view/View;)V

    .line 4
    .line 5
    .line 6
    const p1, 0x7f0a0142

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2, p1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Landroid/widget/TextView;

    .line 14
    .line 15
    iput-object p1, p0, Ly9/l;->u:Landroid/widget/TextView;

    .line 16
    .line 17
    const p1, 0x7f0a0158

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2, p1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, Landroid/widget/TextView;

    .line 25
    .line 26
    iput-object p1, p0, Ly9/l;->v:Landroid/widget/TextView;

    .line 27
    .line 28
    const p1, 0x7f0a0140

    .line 29
    .line 30
    .line 31
    invoke-virtual {p2, p1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    check-cast p1, Landroid/widget/ImageView;

    .line 36
    .line 37
    iput-object p1, p0, Ly9/l;->w:Landroid/widget/ImageView;

    .line 38
    .line 39
    new-instance p1, Ly9/e;

    .line 40
    .line 41
    const/4 v0, 0x2

    .line 42
    invoke-direct {p1, p0, v0}, Ly9/e;-><init>(Ljava/lang/Object;I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p2, p1}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method
