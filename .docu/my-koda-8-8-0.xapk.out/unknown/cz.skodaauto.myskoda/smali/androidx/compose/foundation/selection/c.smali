.class public final Landroidx/compose/foundation/selection/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Le1/s0;

.field public final synthetic e:Lf4/a;

.field public final synthetic f:Z

.field public final synthetic g:Ld4/i;

.field public final synthetic h:Lay0/a;


# direct methods
.method public constructor <init>(Le1/s0;Lf4/a;ZLd4/i;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/selection/c;->d:Le1/s0;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/foundation/selection/c;->e:Lf4/a;

    .line 7
    .line 8
    iput-boolean p3, p0, Landroidx/compose/foundation/selection/c;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Landroidx/compose/foundation/selection/c;->g:Ld4/i;

    .line 11
    .line 12
    iput-object p5, p0, Landroidx/compose/foundation/selection/c;->h:Lay0/a;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Lx2/s;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 8
    .line 9
    .line 10
    check-cast p2, Ll2/t;

    .line 11
    .line 12
    const p1, -0x5af0b3b9

    .line 13
    .line 14
    .line 15
    invoke-virtual {p2, p1}, Ll2/t;->Y(I)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    sget-object p3, Ll2/n;->a:Ll2/x0;

    .line 23
    .line 24
    if-ne p1, p3, :cond_0

    .line 25
    .line 26
    invoke-static {p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    :cond_0
    move-object v2, p1

    .line 31
    check-cast v2, Li1/l;

    .line 32
    .line 33
    iget-object p1, p0, Landroidx/compose/foundation/selection/c;->d:Le1/s0;

    .line 34
    .line 35
    invoke-static {v2, p1}, Landroidx/compose/foundation/c;->a(Li1/l;Le1/s0;)Lx2/s;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    new-instance v0, Landroidx/compose/foundation/selection/TriStateToggleableElement;

    .line 40
    .line 41
    iget-object v5, p0, Landroidx/compose/foundation/selection/c;->g:Ld4/i;

    .line 42
    .line 43
    iget-object v6, p0, Landroidx/compose/foundation/selection/c;->h:Lay0/a;

    .line 44
    .line 45
    iget-object v1, p0, Landroidx/compose/foundation/selection/c;->e:Lf4/a;

    .line 46
    .line 47
    const/4 v3, 0x0

    .line 48
    iget-boolean v4, p0, Landroidx/compose/foundation/selection/c;->f:Z

    .line 49
    .line 50
    invoke-direct/range {v0 .. v6}, Landroidx/compose/foundation/selection/TriStateToggleableElement;-><init>(Lf4/a;Li1/l;Le1/s0;ZLd4/i;Lay0/a;)V

    .line 51
    .line 52
    .line 53
    invoke-interface {p1, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    const/4 p1, 0x0

    .line 58
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 59
    .line 60
    .line 61
    return-object p0
.end method
