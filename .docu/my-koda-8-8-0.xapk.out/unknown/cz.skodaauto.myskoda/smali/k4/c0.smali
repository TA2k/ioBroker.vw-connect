.class public final Lk4/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk4/l;


# instance fields
.field public final a:I

.field public final b:Lk4/x;

.field public final c:I

.field public final d:Lk4/w;


# direct methods
.method public constructor <init>(ILk4/x;ILk4/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lk4/c0;->a:I

    .line 5
    .line 6
    iput-object p2, p0, Lk4/c0;->b:Lk4/x;

    .line 7
    .line 8
    iput p3, p0, Lk4/c0;->c:I

    .line 9
    .line 10
    iput-object p4, p0, Lk4/c0;->d:Lk4/w;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final b()Lk4/x;
    .locals 0

    .line 1
    iget-object p0, p0, Lk4/c0;->b:Lk4/x;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lk4/c0;->c:I

    .line 2
    .line 3
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lk4/c0;

    .line 6
    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_1
    check-cast p1, Lk4/c0;

    .line 11
    .line 12
    iget v1, p1, Lk4/c0;->a:I

    .line 13
    .line 14
    iget v2, p0, Lk4/c0;->a:I

    .line 15
    .line 16
    if-eq v2, v1, :cond_2

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_2
    iget-object v1, p0, Lk4/c0;->b:Lk4/x;

    .line 20
    .line 21
    iget-object v2, p1, Lk4/c0;->b:Lk4/x;

    .line 22
    .line 23
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_3
    iget v1, p0, Lk4/c0;->c:I

    .line 31
    .line 32
    iget v2, p1, Lk4/c0;->c:I

    .line 33
    .line 34
    if-ne v1, v2, :cond_5

    .line 35
    .line 36
    iget-object p0, p0, Lk4/c0;->d:Lk4/w;

    .line 37
    .line 38
    iget-object p1, p1, Lk4/c0;->d:Lk4/w;

    .line 39
    .line 40
    invoke-virtual {p0, p1}, Lk4/w;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-nez p0, :cond_4

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_4
    return v0

    .line 48
    :cond_5
    :goto_0
    const/4 p0, 0x0

    .line 49
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lk4/c0;->a:I

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    mul-int/2addr v0, v1

    .line 6
    iget-object v2, p0, Lk4/c0;->b:Lk4/x;

    .line 7
    .line 8
    iget v2, v2, Lk4/x;->d:I

    .line 9
    .line 10
    add-int/2addr v0, v2

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget v2, p0, Lk4/c0;->c:I

    .line 13
    .line 14
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iget-object p0, p0, Lk4/c0;->d:Lk4/w;

    .line 24
    .line 25
    iget-object p0, p0, Lk4/w;->a:Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    add-int/2addr p0, v0

    .line 32
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ResourceFont(resId="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lk4/c0;->a:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", weight="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lk4/c0;->b:Lk4/x;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", style="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget p0, p0, Lk4/c0;->c:I

    .line 29
    .line 30
    if-nez p0, :cond_0

    .line 31
    .line 32
    const-string p0, "Normal"

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v1, 0x1

    .line 36
    if-ne p0, v1, :cond_1

    .line 37
    .line 38
    const-string p0, "Italic"

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    const-string p0, "Invalid"

    .line 42
    .line 43
    :goto_0
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string p0, ", loadingStrategy=Blocking)"

    .line 47
    .line 48
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method
