.class public final Lj3/j0;
.super Li3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:Ll2/j1;

.field public final j:Ll2/j1;

.field public final k:Lj3/e0;

.field public final l:Ll2/g1;

.field public m:F

.field public n:Le3/m;

.field public o:I


# direct methods
.method public constructor <init>(Lj3/c;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Li3/c;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ld3/e;

    .line 5
    .line 6
    const-wide/16 v1, 0x0

    .line 7
    .line 8
    invoke-direct {v0, v1, v2}, Ld3/e;-><init>(J)V

    .line 9
    .line 10
    .line 11
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lj3/j0;->i:Ll2/j1;

    .line 16
    .line 17
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 18
    .line 19
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Lj3/j0;->j:Ll2/j1;

    .line 24
    .line 25
    new-instance v0, Lj3/e0;

    .line 26
    .line 27
    invoke-direct {v0, p1}, Lj3/e0;-><init>(Lj3/c;)V

    .line 28
    .line 29
    .line 30
    new-instance p1, La7/j;

    .line 31
    .line 32
    const/4 v1, 0x7

    .line 33
    invoke-direct {p1, p0, v1}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lj3/e0;->f:Lkotlin/jvm/internal/n;

    .line 37
    .line 38
    iput-object v0, p0, Lj3/j0;->k:Lj3/e0;

    .line 39
    .line 40
    new-instance p1, Ll2/g1;

    .line 41
    .line 42
    const/4 v0, 0x0

    .line 43
    invoke-direct {p1, v0}, Ll2/g1;-><init>(I)V

    .line 44
    .line 45
    .line 46
    iput-object p1, p0, Lj3/j0;->l:Ll2/g1;

    .line 47
    .line 48
    const/high16 p1, 0x3f800000    # 1.0f

    .line 49
    .line 50
    iput p1, p0, Lj3/j0;->m:F

    .line 51
    .line 52
    const/4 p1, -0x1

    .line 53
    iput p1, p0, Lj3/j0;->o:I

    .line 54
    .line 55
    return-void
.end method


# virtual methods
.method public final a(F)Z
    .locals 0

    .line 1
    iput p1, p0, Lj3/j0;->m:F

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0
.end method

.method public final b(Le3/m;)Z
    .locals 0

    .line 1
    iput-object p1, p0, Lj3/j0;->n:Le3/m;

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0
.end method

.method public final g()J
    .locals 2

    .line 1
    iget-object p0, p0, Lj3/j0;->i:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ld3/e;

    .line 8
    .line 9
    iget-wide v0, p0, Ld3/e;->a:J

    .line 10
    .line 11
    return-wide v0
.end method

.method public final i(Lg3/d;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lj3/j0;->n:Le3/m;

    .line 2
    .line 3
    iget-object v1, p0, Lj3/j0;->k:Lj3/e0;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object v0, v1, Lj3/e0;->g:Ll2/j1;

    .line 8
    .line 9
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Le3/m;

    .line 14
    .line 15
    :cond_0
    iget-object v2, p0, Lj3/j0;->j:Ll2/j1;

    .line 16
    .line 17
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Ljava/lang/Boolean;

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    invoke-interface {p1}, Lg3/d;->getLayoutDirection()Lt4/m;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    sget-object v3, Lt4/m;->e:Lt4/m;

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    invoke-interface {p1}, Lg3/d;->D0()J

    .line 38
    .line 39
    .line 40
    move-result-wide v2

    .line 41
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    invoke-virtual {v4}, Lgw0/c;->o()J

    .line 46
    .line 47
    .line 48
    move-result-wide v5

    .line 49
    invoke-virtual {v4}, Lgw0/c;->h()Le3/r;

    .line 50
    .line 51
    .line 52
    move-result-object v7

    .line 53
    invoke-interface {v7}, Le3/r;->o()V

    .line 54
    .line 55
    .line 56
    :try_start_0
    iget-object v7, v4, Lgw0/c;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v7, Lbu/c;

    .line 59
    .line 60
    const/high16 v8, -0x40800000    # -1.0f

    .line 61
    .line 62
    const/high16 v9, 0x3f800000    # 1.0f

    .line 63
    .line 64
    invoke-virtual {v7, v2, v3, v8, v9}, Lbu/c;->A(JFF)V

    .line 65
    .line 66
    .line 67
    iget v2, p0, Lj3/j0;->m:F

    .line 68
    .line 69
    invoke-virtual {v1, p1, v2, v0}, Lj3/e0;->e(Lg3/d;FLe3/m;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 70
    .line 71
    .line 72
    invoke-static {v4, v5, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :catchall_0
    move-exception p0

    .line 77
    invoke-static {v4, v5, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_1
    iget v2, p0, Lj3/j0;->m:F

    .line 82
    .line 83
    invoke-virtual {v1, p1, v2, v0}, Lj3/e0;->e(Lg3/d;FLe3/m;)V

    .line 84
    .line 85
    .line 86
    :goto_0
    iget-object p1, p0, Lj3/j0;->l:Ll2/g1;

    .line 87
    .line 88
    invoke-virtual {p1}, Ll2/g1;->o()I

    .line 89
    .line 90
    .line 91
    move-result p1

    .line 92
    iput p1, p0, Lj3/j0;->o:I

    .line 93
    .line 94
    return-void
.end method
