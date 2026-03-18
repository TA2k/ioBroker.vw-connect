.class public final Lz4/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ld5/f;

.field public b:I

.field public final c:I

.field public d:I

.field public e:Lt1/j0;

.field public f:I

.field public final g:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v0, Ld5/f;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    new-array v1, v1, [C

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ld5/b;-><init>([C)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lz4/k;->a:Ld5/f;

    .line 18
    .line 19
    const/16 v0, 0x3e8

    .line 20
    .line 21
    iput v0, p0, Lz4/k;->c:I

    .line 22
    .line 23
    iput v0, p0, Lz4/k;->d:I

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    iput v0, p0, Lz4/k;->f:I

    .line 27
    .line 28
    new-instance v0, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lz4/k;->g:Ljava/util/ArrayList;

    .line 34
    .line 35
    return-void
.end method

.method public static b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;
    .locals 1

    .line 1
    new-instance v0, Lz4/j;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Lz4/j;-><init>(Lz4/f;Lay0/k;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method


# virtual methods
.method public final a(Lz4/o;)Ld5/f;
    .locals 4

    .line 1
    invoke-virtual {p1}, Lz4/o;->a()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-object p0, p0, Lz4/k;->a:Ld5/f;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ld5/b;->x(Ljava/lang/String;)Ld5/c;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    instance-of v1, v0, Ld5/f;

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    check-cast v0, Ld5/f;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    if-nez v0, :cond_1

    .line 24
    .line 25
    new-instance v0, Ld5/f;

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    new-array v1, v1, [C

    .line 29
    .line 30
    invoke-direct {v0, v1}, Ld5/b;-><init>([C)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, p1, v0}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    invoke-virtual {p0, p1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    instance-of v1, v0, Ld5/f;

    .line 41
    .line 42
    if-eqz v1, :cond_2

    .line 43
    .line 44
    check-cast v0, Ld5/f;

    .line 45
    .line 46
    return-object v0

    .line 47
    :cond_2
    new-instance v1, Ld5/g;

    .line 48
    .line 49
    const-string v2, "no object found for key <"

    .line 50
    .line 51
    const-string v3, ">, found ["

    .line 52
    .line 53
    invoke-static {v2, p1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-virtual {v0}, Ld5/c;->m()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v2, "] : "

    .line 65
    .line 66
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    invoke-direct {v1, p1, p0}, Ld5/g;-><init>(Ljava/lang/String;Ld5/c;)V

    .line 77
    .line 78
    .line 79
    throw v1
.end method

.method public final c()Lz4/f;
    .locals 2

    .line 1
    iget v0, p0, Lz4/k;->f:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    iput v1, p0, Lz4/k;->f:I

    .line 6
    .line 7
    iget-object v1, p0, Lz4/k;->g:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-static {v0, v1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lz4/f;

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    new-instance v0, Lz4/f;

    .line 18
    .line 19
    iget p0, p0, Lz4/k;->f:I

    .line 20
    .line 21
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-direct {v0, p0}, Lz4/f;-><init>(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    :cond_0
    return-object v0
.end method

.method public final d()Lt1/j0;
    .locals 2

    .line 1
    iget-object v0, p0, Lz4/k;->e:Lt1/j0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lt1/j0;

    .line 6
    .line 7
    const/16 v1, 0x16

    .line 8
    .line 9
    invoke-direct {v0, p0, v1}, Lt1/j0;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lz4/k;->e:Lt1/j0;

    .line 13
    .line 14
    :cond_0
    return-object v0
.end method

.method public final e()V
    .locals 1

    .line 1
    iget-object v0, p0, Lz4/k;->a:Ld5/f;

    .line 2
    .line 3
    iget-object v0, v0, Ld5/b;->h:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 6
    .line 7
    .line 8
    iget v0, p0, Lz4/k;->c:I

    .line 9
    .line 10
    iput v0, p0, Lz4/k;->d:I

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    iput v0, p0, Lz4/k;->b:I

    .line 14
    .line 15
    iput v0, p0, Lz4/k;->f:I

    .line 16
    .line 17
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Lz4/k;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p1, Lz4/k;

    .line 10
    .line 11
    iget-object p1, p1, Lz4/k;->a:Ld5/f;

    .line 12
    .line 13
    iget-object p0, p0, Lz4/k;->a:Ld5/f;

    .line 14
    .line 15
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lz4/k;->a:Ld5/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld5/b;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
