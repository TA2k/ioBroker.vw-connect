.class public final Lu41/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<Identifier:",
        "Lu41/d;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lu41/b;

.field public static final h:[Llx0/i;

.field public static final i:Luz0/d1;


# instance fields
.field public final a:Lu41/d;

.field public final b:Ljava/time/OffsetDateTime;

.field public final c:Z

.field public final d:Ljava/util/Map;

.field public final e:Z

.field public final f:Ljava/util/List;

.field public final g:Ljava/util/Map;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lu41/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lu41/f;->Companion:Lu41/b;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Lt61/d;

    .line 11
    .line 12
    const/16 v2, 0x18

    .line 13
    .line 14
    invoke-direct {v1, v2}, Lt61/d;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v2, Lt61/d;

    .line 22
    .line 23
    const/16 v3, 0x19

    .line 24
    .line 25
    invoke-direct {v2, v3}, Lt61/d;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const/4 v2, 0x7

    .line 33
    new-array v3, v2, [Llx0/i;

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    const/4 v5, 0x0

    .line 37
    aput-object v5, v3, v4

    .line 38
    .line 39
    const/4 v6, 0x1

    .line 40
    aput-object v5, v3, v6

    .line 41
    .line 42
    const/4 v7, 0x2

    .line 43
    aput-object v5, v3, v7

    .line 44
    .line 45
    const/4 v7, 0x3

    .line 46
    aput-object v1, v3, v7

    .line 47
    .line 48
    const/4 v1, 0x4

    .line 49
    aput-object v5, v3, v1

    .line 50
    .line 51
    const/4 v1, 0x5

    .line 52
    aput-object v0, v3, v1

    .line 53
    .line 54
    const/4 v0, 0x6

    .line 55
    aput-object v5, v3, v0

    .line 56
    .line 57
    sput-object v3, Lu41/f;->h:[Llx0/i;

    .line 58
    .line 59
    new-instance v0, Luz0/d1;

    .line 60
    .line 61
    const-string v1, "technology.cariad.cat.capabilities.Capability"

    .line 62
    .line 63
    invoke-direct {v0, v1, v5, v2}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 64
    .line 65
    .line 66
    const-string v1, "id"

    .line 67
    .line 68
    invoke-virtual {v0, v1, v4}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 69
    .line 70
    .line 71
    const-string v1, "expirationDate"

    .line 72
    .line 73
    invoke-virtual {v0, v1, v6}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 74
    .line 75
    .line 76
    const-string v1, "userDisablingAllowed"

    .line 77
    .line 78
    invoke-virtual {v0, v1, v4}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 79
    .line 80
    .line 81
    const-string v1, "operations"

    .line 82
    .line 83
    invoke-virtual {v0, v1, v4}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 84
    .line 85
    .line 86
    const-string v1, "isEnabled"

    .line 87
    .line 88
    invoke-virtual {v0, v1, v4}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 89
    .line 90
    .line 91
    const-string v1, "status"

    .line 92
    .line 93
    invoke-virtual {v0, v1, v4}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 94
    .line 95
    .line 96
    const-string v1, "parameters"

    .line 97
    .line 98
    invoke-virtual {v0, v1, v6}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 99
    .line 100
    .line 101
    sput-object v0, Lu41/f;->i:Luz0/d1;

    .line 102
    .line 103
    return-void
.end method

.method public constructor <init>(ILu41/d;Ljava/time/OffsetDateTime;ZLjava/util/Map;ZLjava/util/List;Ljava/util/Map;)V
    .locals 3

    .line 1
    and-int/lit8 v0, p1, 0x3d

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x3d

    .line 5
    .line 6
    if-ne v2, v0, :cond_2

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p2, p0, Lu41/f;->a:Lu41/d;

    .line 12
    .line 13
    and-int/lit8 p2, p1, 0x2

    .line 14
    .line 15
    if-nez p2, :cond_0

    .line 16
    .line 17
    iput-object v1, p0, Lu41/f;->b:Ljava/time/OffsetDateTime;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    iput-object p3, p0, Lu41/f;->b:Ljava/time/OffsetDateTime;

    .line 21
    .line 22
    :goto_0
    iput-boolean p4, p0, Lu41/f;->c:Z

    .line 23
    .line 24
    iput-object p5, p0, Lu41/f;->d:Ljava/util/Map;

    .line 25
    .line 26
    iput-boolean p6, p0, Lu41/f;->e:Z

    .line 27
    .line 28
    iput-object p7, p0, Lu41/f;->f:Ljava/util/List;

    .line 29
    .line 30
    and-int/lit8 p1, p1, 0x40

    .line 31
    .line 32
    if-nez p1, :cond_1

    .line 33
    .line 34
    sget-object p1, Lmx0/t;->d:Lmx0/t;

    .line 35
    .line 36
    iput-object p1, p0, Lu41/f;->g:Ljava/util/Map;

    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    iput-object p8, p0, Lu41/f;->g:Ljava/util/Map;

    .line 40
    .line 41
    return-void

    .line 42
    :cond_2
    sget-object p0, Lu41/f;->i:Luz0/d1;

    .line 43
    .line 44
    invoke-static {p1, v2, p0}, Luz0/b1;->l(IILsz0/g;)V

    .line 45
    .line 46
    .line 47
    throw v1
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
    instance-of v1, p1, Lu41/f;

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
    check-cast p1, Lu41/f;

    .line 12
    .line 13
    iget-object v1, p0, Lu41/f;->a:Lu41/d;

    .line 14
    .line 15
    iget-object v3, p1, Lu41/f;->a:Lu41/d;

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
    iget-object v1, p0, Lu41/f;->b:Ljava/time/OffsetDateTime;

    .line 25
    .line 26
    iget-object v3, p1, Lu41/f;->b:Ljava/time/OffsetDateTime;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-boolean v1, p0, Lu41/f;->c:Z

    .line 36
    .line 37
    iget-boolean v3, p1, Lu41/f;->c:Z

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lu41/f;->d:Ljava/util/Map;

    .line 43
    .line 44
    iget-object v3, p1, Lu41/f;->d:Ljava/util/Map;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-boolean v1, p0, Lu41/f;->e:Z

    .line 54
    .line 55
    iget-boolean v3, p1, Lu41/f;->e:Z

    .line 56
    .line 57
    if-eq v1, v3, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-object v1, p0, Lu41/f;->f:Ljava/util/List;

    .line 61
    .line 62
    iget-object v3, p1, Lu41/f;->f:Ljava/util/List;

    .line 63
    .line 64
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-object p0, p0, Lu41/f;->g:Ljava/util/Map;

    .line 72
    .line 73
    iget-object p1, p1, Lu41/f;->g:Ljava/util/Map;

    .line 74
    .line 75
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-nez p0, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lu41/f;->a:Lu41/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Lu41/f;->b:Ljava/time/OffsetDateTime;

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v2}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    :goto_0
    add-int/2addr v0, v2

    .line 21
    mul-int/2addr v0, v1

    .line 22
    iget-boolean v2, p0, Lu41/f;->c:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lu41/f;->d:Ljava/util/Map;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lp3/m;->a(IILjava/util/Map;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Lu41/f;->e:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object v2, p0, Lu41/f;->f:Ljava/util/List;

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object p0, p0, Lu41/f;->g:Ljava/util/Map;

    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    add-int/2addr p0, v0

    .line 53
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Parameters(parameters="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lu41/f;->g:Ljava/util/Map;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ")"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    new-instance v2, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v3, "Capability(id="

    .line 25
    .line 26
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object v3, p0, Lu41/f;->a:Lu41/d;

    .line 30
    .line 31
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v3, ", expirationDate="

    .line 35
    .line 36
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    iget-object v3, p0, Lu41/f;->b:Ljava/time/OffsetDateTime;

    .line 40
    .line 41
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v3, ", isUserDisablingAllowed="

    .line 45
    .line 46
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-boolean v3, p0, Lu41/f;->c:Z

    .line 50
    .line 51
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v3, ", operations="

    .line 55
    .line 56
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    iget-object v3, p0, Lu41/f;->d:Ljava/util/Map;

    .line 60
    .line 61
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string v3, ", isEnabled="

    .line 65
    .line 66
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    iget-boolean v3, p0, Lu41/f;->e:Z

    .line 70
    .line 71
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v3, ", status="

    .line 75
    .line 76
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget-object p0, p0, Lu41/f;->f:Ljava/util/List;

    .line 80
    .line 81
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string p0, ", parameters="

    .line 85
    .line 86
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-static {v2, v0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0
.end method
