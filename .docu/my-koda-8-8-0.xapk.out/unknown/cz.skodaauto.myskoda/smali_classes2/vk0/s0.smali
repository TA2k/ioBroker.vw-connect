.class public final Lvk0/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvk0/j0;


# instance fields
.field public final a:Lvk0/d;

.field public final b:Lvk0/l0;


# direct methods
.method public constructor <init>(Lvk0/d;Lvk0/l0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvk0/s0;->a:Lvk0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lvk0/s0;->b:Lvk0/l0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->m:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->e:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final c()Lvk0/l;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->h:Lvk0/l;

    .line 4
    .line 5
    return-object p0
.end method

.method public final d()Lvk0/i0;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->k:Lvk0/i0;

    .line 4
    .line 5
    return-object p0
.end method

.method public final e()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->j:Ljava/util/List;

    .line 4
    .line 5
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lvk0/s0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lvk0/s0;

    .line 12
    .line 13
    iget-object v1, p0, Lvk0/s0;->a:Lvk0/d;

    .line 14
    .line 15
    iget-object v3, p1, Lvk0/s0;->a:Lvk0/d;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object p0, p0, Lvk0/s0;->b:Lvk0/l0;

    .line 25
    .line 26
    iget-object p1, p1, Lvk0/s0;->b:Lvk0/l0;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    return v0
.end method

.method public final f()Lvk0/y;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->n:Lvk0/y;

    .line 4
    .line 5
    return-object p0
.end method

.method public final g()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->g:Ljava/util/List;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getAddress()Lbl0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->d:Lbl0/a;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getDescription()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->c:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->a:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getLocation()Lxj0/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->f:Lxj0/f;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->b:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public final h()Loo0/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->l:Loo0/b;

    .line 4
    .line 5
    return-object p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lvk0/d;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Lvk0/s0;->b:Lvk0/l0;

    .line 10
    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    iget p0, p0, Lvk0/l0;->a:I

    .line 16
    .line 17
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    :goto_0
    add-int/2addr v0, p0

    .line 22
    return v0
.end method

.method public final i()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lvk0/s0;->a:Lvk0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 4
    .line 5
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Restaurant(detail="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lvk0/s0;->a:Lvk0/d;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", priceLevel="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lvk0/s0;->b:Lvk0/l0;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
