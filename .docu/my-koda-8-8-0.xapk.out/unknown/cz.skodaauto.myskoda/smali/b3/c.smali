.class public final Lb3/c;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/j1;
.implements Lb3/b;
.implements Lv3/p;


# instance fields
.field public final r:Lb3/d;

.field public s:Z

.field public t:Lay0/k;


# direct methods
.method public constructor <init>(Lb3/d;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb3/c;->r:Lb3/d;

    .line 5
    .line 6
    iput-object p2, p0, Lb3/c;->t:Lay0/k;

    .line 7
    .line 8
    iput-object p0, p1, Lb3/d;->d:Lb3/b;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lb3/c;->s:Z

    .line 2
    .line 3
    iget-object v1, p0, Lb3/c;->r:Lb3/d;

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput-object v0, v1, Lb3/d;->e:Lb3/g;

    .line 9
    .line 10
    new-instance v0, La4/b;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v2, p0, v1}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-static {p0, v0}, Lv3/f;->t(Lx2/r;Lay0/a;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, v1, Lb3/d;->e:Lb3/g;

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    iput-boolean v0, p0, Lb3/c;->s:Z

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const-string p0, "DrawResult not defined, did you forget to call onDraw?"

    .line 28
    .line 29
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    throw p0

    .line 34
    :cond_1
    :goto_0
    iget-object p0, v1, Lb3/d;->e:Lb3/g;

    .line 35
    .line 36
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Lb3/g;->d:Lay0/k;

    .line 40
    .line 41
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public final E()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lb3/c;->X0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final O()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lb3/c;->X0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final Q0()V
    .locals 0

    .line 1
    return-void
.end method

.method public final R0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lb3/c;->X0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final X0()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lb3/c;->s:Z

    .line 3
    .line 4
    iget-object v0, p0, Lb3/c;->r:Lb3/d;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    iput-object v1, v0, Lb3/d;->e:Lb3/g;

    .line 8
    .line 9
    invoke-static {p0}, Lv3/f;->m(Lv3/p;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final a()Lt4/c;
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 6
    .line 7
    return-object p0
.end method

.method public final d()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lb3/c;->X0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final e()J
    .locals 2

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    invoke-static {p0, v0}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-wide v0, p0, Lt3/e1;->f:J

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkp/f9;->c(J)J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    return-wide v0
.end method

.method public final getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv3/h0;->B:Lt4/m;

    .line 6
    .line 7
    return-object p0
.end method

.method public final m0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lb3/c;->X0()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
