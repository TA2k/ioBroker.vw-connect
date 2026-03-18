.class public final Lf7/k;
.super Ly6/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public c:Ly6/q;

.field public d:Lf7/c;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x3

    .line 3
    invoke-direct {p0, v0, v1}, Ly6/n;-><init>(II)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ly6/o;->a:Ly6/o;

    .line 7
    .line 8
    iput-object v0, p0, Lf7/k;->c:Ly6/q;

    .line 9
    .line 10
    sget-object v0, Lf7/c;->c:Lf7/c;

    .line 11
    .line 12
    iput-object v0, p0, Lf7/k;->d:Lf7/c;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Ly6/q;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lf7/k;->c:Ly6/q;

    .line 2
    .line 3
    return-void
.end method

.method public final b()Ly6/q;
    .locals 0

    .line 1
    iget-object p0, p0, Lf7/k;->c:Ly6/q;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy()Ly6/l;
    .locals 3

    .line 1
    new-instance v0, Lf7/k;

    .line 2
    .line 3
    invoke-direct {v0}, Lf7/k;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lf7/k;->c:Ly6/q;

    .line 7
    .line 8
    iput-object v1, v0, Lf7/k;->c:Ly6/q;

    .line 9
    .line 10
    iget-object v1, p0, Lf7/k;->d:Lf7/c;

    .line 11
    .line 12
    iput-object v1, v0, Lf7/k;->d:Lf7/c;

    .line 13
    .line 14
    new-instance v1, Ljava/util/ArrayList;

    .line 15
    .line 16
    const/16 v2, 0xa

    .line 17
    .line 18
    iget-object p0, p0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-static {p0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_0

    .line 36
    .line 37
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    check-cast v2, Ly6/l;

    .line 42
    .line 43
    invoke-interface {v2}, Ly6/l;->copy()Ly6/l;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    iget-object p0, v0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 54
    .line 55
    .line 56
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "EmittableBox(modifier="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lf7/k;->c:Ly6/q;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", contentAlignment="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lf7/k;->d:Lf7/c;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, "children=[\n"

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Ly6/n;->c()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string p0, "\n])"

    .line 36
    .line 37
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method
