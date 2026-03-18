.class public final Lom/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbm/j;


# instance fields
.field public final a:Lom/c;

.field public final b:Lay0/k;

.field public final c:Z

.field public final d:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lom/c;->d:Lom/c;

    .line 5
    .line 6
    iput-object v0, p0, Lom/e;->a:Lom/c;

    .line 7
    .line 8
    sget-object v0, Lom/f;->g:Lod0/g;

    .line 9
    .line 10
    iput-object v0, p0, Lom/e;->b:Lay0/k;

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    iput-boolean v0, p0, Lom/e;->c:Z

    .line 14
    .line 15
    iput-boolean v0, p0, Lom/e;->d:Z

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(Ldm/i;Lmm/n;)Lbm/k;
    .locals 7

    .line 1
    iget-object v0, p1, Ldm/i;->b:Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "image/svg+xml"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    iget-object v0, p1, Ldm/i;->a:Lbm/q;

    .line 12
    .line 13
    invoke-interface {v0}, Lbm/q;->p0()Lu01/h;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-wide/16 v1, 0x0

    .line 18
    .line 19
    sget-object v3, Lom/a;->b:Lu01/i;

    .line 20
    .line 21
    invoke-interface {v0, v1, v2, v3}, Lu01/h;->v(JLu01/i;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    sget-object v1, Lom/a;->a:Lu01/i;

    .line 28
    .line 29
    const-wide/16 v2, 0x400

    .line 30
    .line 31
    invoke-interface {v0, v2, v3, v1}, Lu01/h;->D(JLu01/i;)J

    .line 32
    .line 33
    .line 34
    move-result-wide v0

    .line 35
    const-wide/16 v2, -0x1

    .line 36
    .line 37
    cmp-long v0, v0, v2

    .line 38
    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 p0, 0x0

    .line 43
    return-object p0

    .line 44
    :cond_1
    :goto_0
    new-instance v0, Lom/f;

    .line 45
    .line 46
    iget-object v1, p1, Ldm/i;->a:Lbm/q;

    .line 47
    .line 48
    iget-boolean v5, p0, Lom/e;->c:Z

    .line 49
    .line 50
    iget-boolean v6, p0, Lom/e;->d:Z

    .line 51
    .line 52
    iget-object v3, p0, Lom/e;->a:Lom/c;

    .line 53
    .line 54
    iget-object v4, p0, Lom/e;->b:Lay0/k;

    .line 55
    .line 56
    move-object v2, p2

    .line 57
    invoke-direct/range {v0 .. v6}, Lom/f;-><init>(Lbm/q;Lmm/n;Lom/c;Lay0/k;ZZ)V

    .line 58
    .line 59
    .line 60
    return-object v0
.end method
