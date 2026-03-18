.class public final synthetic Lq1/d;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Lq1/e;

.field public final synthetic e:Lv3/f1;

.field public final synthetic f:La4/b;


# direct methods
.method public constructor <init>(Lq1/e;Lv3/f1;La4/b;)V
    .locals 6

    .line 1
    iput-object p1, p0, Lq1/d;->d:Lq1/e;

    .line 2
    .line 3
    iput-object p2, p0, Lq1/d;->e:Lv3/f1;

    .line 4
    .line 5
    iput-object p3, p0, Lq1/d;->f:La4/b;

    .line 6
    .line 7
    const-string v4, "bringIntoView$localRect(Landroidx/compose/foundation/relocation/BringIntoViewResponderNode;Landroidx/compose/ui/layout/LayoutCoordinates;Lkotlin/jvm/functions/Function0;)Landroidx/compose/ui/geometry/Rect;"

    .line 8
    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v1, 0x0

    .line 11
    const-class v2, Lkotlin/jvm/internal/l;

    .line 12
    .line 13
    const-string v3, "localRect"

    .line 14
    .line 15
    move-object v0, p0

    .line 16
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lq1/d;->e:Lv3/f1;

    .line 2
    .line 3
    iget-object v1, p0, Lq1/d;->f:La4/b;

    .line 4
    .line 5
    iget-object p0, p0, Lq1/d;->d:Lq1/e;

    .line 6
    .line 7
    invoke-static {p0, v0, v1}, Lq1/e;->X0(Lq1/e;Lv3/f1;La4/b;)Ld3/c;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
