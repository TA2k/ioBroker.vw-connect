.class public final Lb2/c;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/t1;
.implements Lc3/e;
.implements Lc3/r;


# instance fields
.field public t:Lay0/a;

.field public u:Z

.field public final v:Lp3/j0;


# direct methods
.method public constructor <init>(Lay0/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb2/c;->t:Lay0/a;

    .line 5
    .line 6
    new-instance p1, Lb2/b;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {p1, p0, v0}, Lb2/b;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Lp3/f0;->a(Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lp3/j0;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p0, p1}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lb2/c;->v:Lp3/j0;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final F(Lc3/u;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Lc3/u;->b()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iput-boolean p1, p0, Lb2/c;->u:Z

    .line 6
    .line 7
    return-void
.end method

.method public final b0()J
    .locals 4

    .line 1
    sget-object v0, Landroidx/compose/foundation/text/handwriting/a;->a:Lv3/o;

    .line 2
    .line 3
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    sget v1, Lv3/a2;->b:I

    .line 13
    .line 14
    iget v1, v0, Lv3/o;->a:F

    .line 15
    .line 16
    invoke-interface {p0, v1}, Lt4/c;->Q(F)I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    iget v2, v0, Lv3/o;->b:F

    .line 21
    .line 22
    invoke-interface {p0, v2}, Lt4/c;->Q(F)I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    iget v3, v0, Lv3/o;->c:F

    .line 27
    .line 28
    invoke-interface {p0, v3}, Lt4/c;->Q(F)I

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    iget v0, v0, Lv3/o;->d:F

    .line 33
    .line 34
    invoke-interface {p0, v0}, Lt4/c;->Q(F)I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    invoke-static {v1, v2, v3, p0}, Lv3/d;->d(IIII)J

    .line 39
    .line 40
    .line 41
    move-result-wide v0

    .line 42
    return-wide v0
.end method

.method public final l0()V
    .locals 0

    .line 1
    iget-object p0, p0, Lb2/c;->v:Lp3/j0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lp3/j0;->l0()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final v0(Lp3/k;Lp3/l;J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lb2/c;->v:Lp3/j0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3, p4}, Lp3/j0;->v0(Lp3/k;Lp3/l;J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
