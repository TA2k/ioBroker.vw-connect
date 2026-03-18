.class public final Lca/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lz9/k;

.field public final b:Lz9/u;

.field public final c:Landroid/os/Bundle;

.field public d:Landroidx/lifecycle/q;

.field public final e:Lz9/n;

.field public final f:Ljava/lang/String;

.field public final g:Landroid/os/Bundle;

.field public final h:Lra/e;

.field public i:Z

.field public final j:Landroidx/lifecycle/z;

.field public k:Landroidx/lifecycle/q;

.field public final l:Landroidx/lifecycle/y0;

.field public final m:Llx0/q;


# direct methods
.method public constructor <init>(Lz9/k;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lca/c;->a:Lz9/k;

    .line 5
    .line 6
    iget-object v0, p1, Lz9/k;->e:Lz9/u;

    .line 7
    .line 8
    iput-object v0, p0, Lca/c;->b:Lz9/u;

    .line 9
    .line 10
    iget-object v0, p1, Lz9/k;->f:Landroid/os/Bundle;

    .line 11
    .line 12
    iput-object v0, p0, Lca/c;->c:Landroid/os/Bundle;

    .line 13
    .line 14
    iget-object v0, p1, Lz9/k;->g:Landroidx/lifecycle/q;

    .line 15
    .line 16
    iput-object v0, p0, Lca/c;->d:Landroidx/lifecycle/q;

    .line 17
    .line 18
    iget-object v0, p1, Lz9/k;->h:Lz9/n;

    .line 19
    .line 20
    iput-object v0, p0, Lca/c;->e:Lz9/n;

    .line 21
    .line 22
    iget-object v0, p1, Lz9/k;->i:Ljava/lang/String;

    .line 23
    .line 24
    iput-object v0, p0, Lca/c;->f:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v0, p1, Lz9/k;->j:Landroid/os/Bundle;

    .line 27
    .line 28
    iput-object v0, p0, Lca/c;->g:Landroid/os/Bundle;

    .line 29
    .line 30
    new-instance v0, Lg11/c;

    .line 31
    .line 32
    new-instance v1, Lr1/b;

    .line 33
    .line 34
    const/4 v2, 0x6

    .line 35
    invoke-direct {v1, p1, v2}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 36
    .line 37
    .line 38
    invoke-direct {v0, p1, v1}, Lg11/c;-><init>(Lra/f;Lr1/b;)V

    .line 39
    .line 40
    .line 41
    new-instance v1, Lra/e;

    .line 42
    .line 43
    invoke-direct {v1, v0}, Lra/e;-><init>(Lg11/c;)V

    .line 44
    .line 45
    .line 46
    iput-object v1, p0, Lca/c;->h:Lra/e;

    .line 47
    .line 48
    new-instance v0, Lc91/u;

    .line 49
    .line 50
    const/16 v1, 0xc

    .line 51
    .line 52
    invoke-direct {v0, v1}, Lc91/u;-><init>(I)V

    .line 53
    .line 54
    .line 55
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    new-instance v1, Landroidx/lifecycle/z;

    .line 60
    .line 61
    const/4 v2, 0x1

    .line 62
    invoke-direct {v1, p1, v2}, Landroidx/lifecycle/z;-><init>(Landroidx/lifecycle/x;Z)V

    .line 63
    .line 64
    .line 65
    iput-object v1, p0, Lca/c;->j:Landroidx/lifecycle/z;

    .line 66
    .line 67
    sget-object p1, Landroidx/lifecycle/q;->e:Landroidx/lifecycle/q;

    .line 68
    .line 69
    iput-object p1, p0, Lca/c;->k:Landroidx/lifecycle/q;

    .line 70
    .line 71
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    check-cast p1, Landroidx/lifecycle/y0;

    .line 76
    .line 77
    iput-object p1, p0, Lca/c;->l:Landroidx/lifecycle/y0;

    .line 78
    .line 79
    new-instance p1, Lc91/u;

    .line 80
    .line 81
    const/16 v0, 0xd

    .line 82
    .line 83
    invoke-direct {p1, v0}, Lc91/u;-><init>(I)V

    .line 84
    .line 85
    .line 86
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    iput-object p1, p0, Lca/c;->m:Llx0/q;

    .line 91
    .line 92
    return-void
.end method


# virtual methods
.method public final a()Landroid/os/Bundle;
    .locals 2

    .line 1
    iget-object p0, p0, Lca/c;->c:Landroid/os/Bundle;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    new-array v1, v0, [Llx0/l;

    .line 9
    .line 10
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, [Llx0/l;

    .line 15
    .line 16
    invoke-static {v0}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0, p0}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    .line 21
    .line 22
    .line 23
    return-object v0
.end method

.method public final b()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lca/c;->i:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lca/c;->h:Lra/e;

    .line 6
    .line 7
    invoke-virtual {v0}, Lra/e;->a()V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iput-boolean v1, p0, Lca/c;->i:Z

    .line 12
    .line 13
    iget-object v1, p0, Lca/c;->e:Lz9/n;

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    iget-object v1, p0, Lca/c;->a:Lz9/k;

    .line 18
    .line 19
    invoke-static {v1}, Landroidx/lifecycle/v0;->c(Lra/f;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    iget-object v1, p0, Lca/c;->g:Landroid/os/Bundle;

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Lra/e;->b(Landroid/os/Bundle;)V

    .line 25
    .line 26
    .line 27
    :cond_1
    iget-object v0, p0, Lca/c;->d:Landroidx/lifecycle/q;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    iget-object v1, p0, Lca/c;->k:Landroidx/lifecycle/q;

    .line 34
    .line 35
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    iget-object v2, p0, Lca/c;->j:Landroidx/lifecycle/z;

    .line 40
    .line 41
    if-ge v0, v1, :cond_2

    .line 42
    .line 43
    iget-object p0, p0, Lca/c;->d:Landroidx/lifecycle/q;

    .line 44
    .line 45
    invoke-virtual {v2, p0}, Landroidx/lifecycle/z;->i(Landroidx/lifecycle/q;)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :cond_2
    iget-object p0, p0, Lca/c;->k:Landroidx/lifecycle/q;

    .line 50
    .line 51
    invoke-virtual {v2, p0}, Landroidx/lifecycle/z;->i(Landroidx/lifecycle/q;)V

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const-class v1, Lz9/k;

    .line 7
    .line 8
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 9
    .line 10
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-interface {v1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    new-instance v1, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string v2, "("

    .line 24
    .line 25
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object v2, p0, Lca/c;->f:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const/16 v2, 0x29

    .line 34
    .line 35
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v1, " destination="

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    iget-object p0, p0, Lca/c;->b:Lz9/u;

    .line 51
    .line 52
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    const-string v0, "toString(...)"

    .line 60
    .line 61
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return-object p0
.end method
