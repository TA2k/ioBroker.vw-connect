.class public final Ln50/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Lqp0/b0;

.field public final f:Lbl0/n;


# direct methods
.method public constructor <init>(Ljava/lang/String;ZZZLqp0/b0;Lbl0/n;)V
    .locals 1

    .line 1
    const-string v0, "place"

    .line 2
    .line 3
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ln50/a0;->a:Ljava/lang/String;

    .line 10
    .line 11
    iput-boolean p2, p0, Ln50/a0;->b:Z

    .line 12
    .line 13
    iput-boolean p3, p0, Ln50/a0;->c:Z

    .line 14
    .line 15
    iput-boolean p4, p0, Ln50/a0;->d:Z

    .line 16
    .line 17
    iput-object p5, p0, Ln50/a0;->e:Lqp0/b0;

    .line 18
    .line 19
    iput-object p6, p0, Ln50/a0;->f:Lbl0/n;

    .line 20
    .line 21
    return-void
.end method

.method public static a(Ln50/a0;Z)Ln50/a0;
    .locals 7

    .line 1
    iget-object v1, p0, Ln50/a0;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget-boolean v2, p0, Ln50/a0;->b:Z

    .line 4
    .line 5
    iget-boolean v4, p0, Ln50/a0;->d:Z

    .line 6
    .line 7
    iget-object v5, p0, Ln50/a0;->e:Lqp0/b0;

    .line 8
    .line 9
    iget-object v6, p0, Ln50/a0;->f:Lbl0/n;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const-string p0, "place"

    .line 15
    .line 16
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    new-instance v0, Ln50/a0;

    .line 20
    .line 21
    move v3, p1

    .line 22
    invoke-direct/range {v0 .. v6}, Ln50/a0;-><init>(Ljava/lang/String;ZZZLqp0/b0;Lbl0/n;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method


# virtual methods
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
    instance-of v1, p1, Ln50/a0;

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
    check-cast p1, Ln50/a0;

    .line 12
    .line 13
    iget-object v1, p0, Ln50/a0;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ln50/a0;->a:Ljava/lang/String;

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
    iget-boolean v1, p0, Ln50/a0;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Ln50/a0;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Ln50/a0;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Ln50/a0;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Ln50/a0;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Ln50/a0;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-object v1, p0, Ln50/a0;->e:Lqp0/b0;

    .line 46
    .line 47
    iget-object v3, p1, Ln50/a0;->e:Lqp0/b0;

    .line 48
    .line 49
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-object p0, p0, Ln50/a0;->f:Lbl0/n;

    .line 57
    .line 58
    iget-object p1, p1, Ln50/a0;->f:Lbl0/n;

    .line 59
    .line 60
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    if-nez p0, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ln50/a0;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-boolean v2, p0, Ln50/a0;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Ln50/a0;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Ln50/a0;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Ln50/a0;->e:Lqp0/b0;

    .line 29
    .line 30
    invoke-virtual {v2}, Lqp0/b0;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    iget-object p0, p0, Ln50/a0;->f:Lbl0/n;

    .line 37
    .line 38
    invoke-virtual {p0}, Lbl0/n;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    add-int/2addr p0, v2

    .line 43
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isFavouriteVisible="

    .line 2
    .line 3
    const-string v1, ", isFavourite="

    .line 4
    .line 5
    const-string v2, "Detail(direction="

    .line 6
    .line 7
    iget-object v3, p0, Ln50/a0;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Ln50/a0;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1, v4}, Lia/b;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isSendRouteVisible="

    .line 16
    .line 17
    const-string v2, ", waypoint="

    .line 18
    .line 19
    iget-boolean v3, p0, Ln50/a0;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Ln50/a0;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Ln50/a0;->e:Lqp0/b0;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", place="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Ln50/a0;->f:Lbl0/n;

    .line 37
    .line 38
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string p0, ")"

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method
