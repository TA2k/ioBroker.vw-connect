.class public final Leb/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final j:Leb/e;


# instance fields
.field public final a:Leb/x;

.field public final b:Lnb/d;

.field public final c:Z

.field public final d:Z

.field public final e:Z

.field public final f:Z

.field public final g:J

.field public final h:J

.field public final i:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Leb/e;

    .line 2
    .line 3
    invoke-direct {v0}, Leb/e;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Leb/e;->j:Leb/e;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    sget-object v0, Leb/x;->d:Leb/x;

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v1, Lnb/d;

    const/4 v2, 0x0

    .line 4
    invoke-direct {v1, v2}, Lnb/d;-><init>(Landroid/net/NetworkRequest;)V

    .line 5
    iput-object v1, p0, Leb/e;->b:Lnb/d;

    .line 6
    iput-object v0, p0, Leb/e;->a:Leb/x;

    const/4 v0, 0x0

    .line 7
    iput-boolean v0, p0, Leb/e;->c:Z

    .line 8
    iput-boolean v0, p0, Leb/e;->d:Z

    .line 9
    iput-boolean v0, p0, Leb/e;->e:Z

    .line 10
    iput-boolean v0, p0, Leb/e;->f:Z

    const-wide/16 v0, -0x1

    .line 11
    iput-wide v0, p0, Leb/e;->g:J

    .line 12
    iput-wide v0, p0, Leb/e;->h:J

    .line 13
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    iput-object v0, p0, Leb/e;->i:Ljava/util/Set;

    return-void
.end method

.method public constructor <init>(Leb/e;)V
    .locals 2

    const-string v0, "other"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 25
    iget-boolean v0, p1, Leb/e;->c:Z

    iput-boolean v0, p0, Leb/e;->c:Z

    .line 26
    iget-boolean v0, p1, Leb/e;->d:Z

    iput-boolean v0, p0, Leb/e;->d:Z

    .line 27
    iget-object v0, p1, Leb/e;->b:Lnb/d;

    iput-object v0, p0, Leb/e;->b:Lnb/d;

    .line 28
    iget-object v0, p1, Leb/e;->a:Leb/x;

    iput-object v0, p0, Leb/e;->a:Leb/x;

    .line 29
    iget-boolean v0, p1, Leb/e;->e:Z

    iput-boolean v0, p0, Leb/e;->e:Z

    .line 30
    iget-boolean v0, p1, Leb/e;->f:Z

    iput-boolean v0, p0, Leb/e;->f:Z

    .line 31
    iget-object v0, p1, Leb/e;->i:Ljava/util/Set;

    iput-object v0, p0, Leb/e;->i:Ljava/util/Set;

    .line 32
    iget-wide v0, p1, Leb/e;->g:J

    iput-wide v0, p0, Leb/e;->g:J

    .line 33
    iget-wide v0, p1, Leb/e;->h:J

    iput-wide v0, p0, Leb/e;->h:J

    return-void
.end method

.method public constructor <init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V
    .locals 0

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    iput-object p1, p0, Leb/e;->b:Lnb/d;

    .line 16
    iput-object p2, p0, Leb/e;->a:Leb/x;

    .line 17
    iput-boolean p3, p0, Leb/e;->c:Z

    .line 18
    iput-boolean p4, p0, Leb/e;->d:Z

    .line 19
    iput-boolean p5, p0, Leb/e;->e:Z

    .line 20
    iput-boolean p6, p0, Leb/e;->f:Z

    .line 21
    iput-wide p7, p0, Leb/e;->g:J

    .line 22
    iput-wide p9, p0, Leb/e;->h:J

    .line 23
    iput-object p11, p0, Leb/e;->i:Ljava/util/Set;

    return-void
.end method


# virtual methods
.method public final a()Landroid/net/NetworkRequest;
    .locals 0

    .line 1
    iget-object p0, p0, Leb/e;->b:Lnb/d;

    .line 2
    .line 3
    iget-object p0, p0, Lnb/d;->a:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Landroid/net/NetworkRequest;

    .line 6
    .line 7
    return-object p0
.end method

.method public final b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Leb/e;->i:Ljava/util/Set;

    .line 2
    .line 3
    check-cast p0, Ljava/util/Collection;

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    const/4 v0, 0x0

    .line 6
    if-eqz p1, :cond_a

    .line 7
    .line 8
    const-class v1, Leb/e;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    check-cast p1, Leb/e;

    .line 22
    .line 23
    iget-boolean v1, p0, Leb/e;->c:Z

    .line 24
    .line 25
    iget-boolean v2, p1, Leb/e;->c:Z

    .line 26
    .line 27
    if-eq v1, v2, :cond_2

    .line 28
    .line 29
    return v0

    .line 30
    :cond_2
    iget-boolean v1, p0, Leb/e;->d:Z

    .line 31
    .line 32
    iget-boolean v2, p1, Leb/e;->d:Z

    .line 33
    .line 34
    if-eq v1, v2, :cond_3

    .line 35
    .line 36
    return v0

    .line 37
    :cond_3
    iget-boolean v1, p0, Leb/e;->e:Z

    .line 38
    .line 39
    iget-boolean v2, p1, Leb/e;->e:Z

    .line 40
    .line 41
    if-eq v1, v2, :cond_4

    .line 42
    .line 43
    return v0

    .line 44
    :cond_4
    iget-boolean v1, p0, Leb/e;->f:Z

    .line 45
    .line 46
    iget-boolean v2, p1, Leb/e;->f:Z

    .line 47
    .line 48
    if-eq v1, v2, :cond_5

    .line 49
    .line 50
    return v0

    .line 51
    :cond_5
    iget-wide v1, p0, Leb/e;->g:J

    .line 52
    .line 53
    iget-wide v3, p1, Leb/e;->g:J

    .line 54
    .line 55
    cmp-long v1, v1, v3

    .line 56
    .line 57
    if-eqz v1, :cond_6

    .line 58
    .line 59
    return v0

    .line 60
    :cond_6
    iget-wide v1, p0, Leb/e;->h:J

    .line 61
    .line 62
    iget-wide v3, p1, Leb/e;->h:J

    .line 63
    .line 64
    cmp-long v1, v1, v3

    .line 65
    .line 66
    if-eqz v1, :cond_7

    .line 67
    .line 68
    return v0

    .line 69
    :cond_7
    invoke-virtual {p0}, Leb/e;->a()Landroid/net/NetworkRequest;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    invoke-virtual {p1}, Leb/e;->a()Landroid/net/NetworkRequest;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-nez v1, :cond_8

    .line 82
    .line 83
    return v0

    .line 84
    :cond_8
    iget-object v1, p0, Leb/e;->a:Leb/x;

    .line 85
    .line 86
    iget-object v2, p1, Leb/e;->a:Leb/x;

    .line 87
    .line 88
    if-eq v1, v2, :cond_9

    .line 89
    .line 90
    return v0

    .line 91
    :cond_9
    iget-object p0, p0, Leb/e;->i:Ljava/util/Set;

    .line 92
    .line 93
    iget-object p1, p1, Leb/e;->i:Ljava/util/Set;

    .line 94
    .line 95
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    return p0

    .line 100
    :cond_a
    :goto_0
    return v0
.end method

.method public final hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Leb/e;->a:Leb/x;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-boolean v1, p0, Leb/e;->c:Z

    .line 10
    .line 11
    add-int/2addr v0, v1

    .line 12
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-boolean v1, p0, Leb/e;->d:Z

    .line 15
    .line 16
    add-int/2addr v0, v1

    .line 17
    mul-int/lit8 v0, v0, 0x1f

    .line 18
    .line 19
    iget-boolean v1, p0, Leb/e;->e:Z

    .line 20
    .line 21
    add-int/2addr v0, v1

    .line 22
    mul-int/lit8 v0, v0, 0x1f

    .line 23
    .line 24
    iget-boolean v1, p0, Leb/e;->f:Z

    .line 25
    .line 26
    add-int/2addr v0, v1

    .line 27
    mul-int/lit8 v0, v0, 0x1f

    .line 28
    .line 29
    iget-wide v1, p0, Leb/e;->g:J

    .line 30
    .line 31
    const/16 v3, 0x20

    .line 32
    .line 33
    ushr-long v4, v1, v3

    .line 34
    .line 35
    xor-long/2addr v1, v4

    .line 36
    long-to-int v1, v1

    .line 37
    add-int/2addr v0, v1

    .line 38
    mul-int/lit8 v0, v0, 0x1f

    .line 39
    .line 40
    iget-wide v1, p0, Leb/e;->h:J

    .line 41
    .line 42
    ushr-long v3, v1, v3

    .line 43
    .line 44
    xor-long/2addr v1, v3

    .line 45
    long-to-int v1, v1

    .line 46
    add-int/2addr v0, v1

    .line 47
    mul-int/lit8 v0, v0, 0x1f

    .line 48
    .line 49
    iget-object v1, p0, Leb/e;->i:Ljava/util/Set;

    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    add-int/2addr v1, v0

    .line 56
    mul-int/lit8 v1, v1, 0x1f

    .line 57
    .line 58
    invoke-virtual {p0}, Leb/e;->a()Landroid/net/NetworkRequest;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    if-eqz p0, :cond_0

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    goto :goto_0

    .line 69
    :cond_0
    const/4 p0, 0x0

    .line 70
    :goto_0
    add-int/2addr v1, p0

    .line 71
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Constraints{requiredNetworkType="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Leb/e;->a:Leb/x;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", requiresCharging="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Leb/e;->c:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", requiresDeviceIdle="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-boolean v1, p0, Leb/e;->d:Z

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", requiresBatteryNotLow="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-boolean v1, p0, Leb/e;->e:Z

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", requiresStorageNotLow="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Leb/e;->f:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", contentTriggerUpdateDelayMillis="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-wide v1, p0, Leb/e;->g:J

    .line 59
    .line 60
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", contentTriggerMaxDelayMillis="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-wide v1, p0, Leb/e;->h:J

    .line 69
    .line 70
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", contentUriTriggers="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object p0, p0, Leb/e;->i:Ljava/util/Set;

    .line 79
    .line 80
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string p0, ", }"

    .line 84
    .line 85
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0
.end method
