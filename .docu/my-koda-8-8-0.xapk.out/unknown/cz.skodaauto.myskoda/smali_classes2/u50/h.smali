.class public final Lu50/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Lu50/g;

.field public final f:Lql0/g;

.field public final g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 9

    sget-object v0, Lu50/g;->f:Lu50/g;

    and-int/lit8 p1, p1, 0x10

    if-eqz p1, :cond_0

    const/4 v0, 0x0

    :cond_0
    move-object v6, v0

    .line 9
    const-string v8, "https://www.android.com/digital-car-key/"

    const/4 v2, 0x1

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    move-object v1, p0

    .line 10
    invoke-direct/range {v1 .. v8}, Lu50/h;-><init>(ZZZZLu50/g;Lql0/g;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(ZZZZLu50/g;Lql0/g;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-boolean p1, p0, Lu50/h;->a:Z

    .line 3
    iput-boolean p2, p0, Lu50/h;->b:Z

    .line 4
    iput-boolean p3, p0, Lu50/h;->c:Z

    .line 5
    iput-boolean p4, p0, Lu50/h;->d:Z

    .line 6
    iput-object p5, p0, Lu50/h;->e:Lu50/g;

    .line 7
    iput-object p6, p0, Lu50/h;->f:Lql0/g;

    .line 8
    iput-object p7, p0, Lu50/h;->g:Ljava/lang/String;

    return-void
.end method

.method public static a(Lu50/h;ZZZLu50/g;Lql0/g;I)Lu50/h;
    .locals 9

    .line 1
    and-int/lit8 v0, p6, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v0, p0, Lu50/h;->b:Z

    .line 6
    .line 7
    :goto_0
    move v3, v0

    .line 8
    goto :goto_1

    .line 9
    :cond_0
    const/4 v0, 0x1

    .line 10
    goto :goto_0

    .line 11
    :goto_1
    and-int/lit8 v0, p6, 0x4

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    iget-boolean p2, p0, Lu50/h;->c:Z

    .line 16
    .line 17
    :cond_1
    move v4, p2

    .line 18
    and-int/lit8 p2, p6, 0x8

    .line 19
    .line 20
    if-eqz p2, :cond_2

    .line 21
    .line 22
    iget-boolean p3, p0, Lu50/h;->d:Z

    .line 23
    .line 24
    :cond_2
    move v5, p3

    .line 25
    and-int/lit8 p2, p6, 0x10

    .line 26
    .line 27
    if-eqz p2, :cond_3

    .line 28
    .line 29
    iget-object p4, p0, Lu50/h;->e:Lu50/g;

    .line 30
    .line 31
    :cond_3
    move-object v6, p4

    .line 32
    and-int/lit8 p2, p6, 0x20

    .line 33
    .line 34
    if-eqz p2, :cond_4

    .line 35
    .line 36
    iget-object p5, p0, Lu50/h;->f:Lql0/g;

    .line 37
    .line 38
    :cond_4
    move-object v7, p5

    .line 39
    iget-object v8, p0, Lu50/h;->g:Ljava/lang/String;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    const-string p0, "requirementsLink"

    .line 45
    .line 46
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    new-instance v1, Lu50/h;

    .line 50
    .line 51
    move v2, p1

    .line 52
    invoke-direct/range {v1 .. v8}, Lu50/h;-><init>(ZZZZLu50/g;Lql0/g;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    return-object v1
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lu50/h;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lu50/h;

    .line 10
    .line 11
    iget-boolean v0, p0, Lu50/h;->a:Z

    .line 12
    .line 13
    iget-boolean v1, p1, Lu50/h;->a:Z

    .line 14
    .line 15
    if-eq v0, v1, :cond_2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    iget-boolean v0, p0, Lu50/h;->b:Z

    .line 19
    .line 20
    iget-boolean v1, p1, Lu50/h;->b:Z

    .line 21
    .line 22
    if-eq v0, v1, :cond_3

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_3
    iget-boolean v0, p0, Lu50/h;->c:Z

    .line 26
    .line 27
    iget-boolean v1, p1, Lu50/h;->c:Z

    .line 28
    .line 29
    if-eq v0, v1, :cond_4

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_4
    iget-boolean v0, p0, Lu50/h;->d:Z

    .line 33
    .line 34
    iget-boolean v1, p1, Lu50/h;->d:Z

    .line 35
    .line 36
    if-eq v0, v1, :cond_5

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_5
    iget-object v0, p0, Lu50/h;->e:Lu50/g;

    .line 40
    .line 41
    iget-object v1, p1, Lu50/h;->e:Lu50/g;

    .line 42
    .line 43
    if-eq v0, v1, :cond_6

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_6
    iget-object v0, p0, Lu50/h;->f:Lql0/g;

    .line 47
    .line 48
    iget-object v1, p1, Lu50/h;->f:Lql0/g;

    .line 49
    .line 50
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-nez v0, :cond_7

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_7
    iget-object p0, p0, Lu50/h;->g:Ljava/lang/String;

    .line 58
    .line 59
    iget-object p1, p1, Lu50/h;->g:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-nez p0, :cond_8

    .line 66
    .line 67
    :goto_0
    const/4 p0, 0x0

    .line 68
    return p0

    .line 69
    :cond_8
    :goto_1
    const/4 p0, 0x1

    .line 70
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lu50/h;->a:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    iget-boolean v2, p0, Lu50/h;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lu50/h;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lu50/h;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v2, 0x0

    .line 29
    iget-object v3, p0, Lu50/h;->e:Lu50/g;

    .line 30
    .line 31
    if-nez v3, :cond_0

    .line 32
    .line 33
    move v3, v2

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_0
    add-int/2addr v0, v3

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v3, p0, Lu50/h;->f:Lql0/g;

    .line 42
    .line 43
    if-nez v3, :cond_1

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    invoke-virtual {v3}, Lql0/g;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    :goto_1
    add-int/2addr v0, v2

    .line 51
    mul-int/2addr v0, v1

    .line 52
    iget-object p0, p0, Lu50/h;->g:Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    add-int/2addr p0, v0

    .line 59
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isContinueEnabled="

    .line 2
    .line 3
    const-string v1, ", isPaired="

    .line 4
    .line 5
    const-string v2, "State(isLoading="

    .line 6
    .line 7
    iget-boolean v3, p0, Lu50/h;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lu50/h;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isServiceCardActivated="

    .line 16
    .line 17
    const-string v2, ", error="

    .line 18
    .line 19
    iget-boolean v3, p0, Lu50/h;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lu50/h;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lu50/h;->e:Lu50/g;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", displayError="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lu50/h;->f:Lql0/g;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", requirementsLink="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ")"

    .line 47
    .line 48
    iget-object p0, p0, Lu50/h;->g:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method
