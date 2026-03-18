.class public final Lw51/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lw51/b;

.field public final b:Lw51/e;

.field public final c:Lay0/a;

.field public final d:Ljava/lang/String;

.field public final e:I

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/Throwable;

.field public final h:J


# direct methods
.method public constructor <init>(Lw51/b;Lw51/e;Lay0/a;Ljava/lang/String;ILjava/lang/String;Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-string v2, "moduleName"

    .line 6
    .line 7
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "className"

    .line 11
    .line 12
    invoke-static {p4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lw51/f;->a:Lw51/b;

    .line 19
    .line 20
    iput-object p2, p0, Lw51/f;->b:Lw51/e;

    .line 21
    .line 22
    iput-object p3, p0, Lw51/f;->c:Lay0/a;

    .line 23
    .line 24
    iput-object p4, p0, Lw51/f;->d:Ljava/lang/String;

    .line 25
    .line 26
    iput p5, p0, Lw51/f;->e:I

    .line 27
    .line 28
    iput-object p6, p0, Lw51/f;->f:Ljava/lang/String;

    .line 29
    .line 30
    iput-object p7, p0, Lw51/f;->g:Ljava/lang/Throwable;

    .line 31
    .line 32
    iput-wide v0, p0, Lw51/f;->h:J

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lw51/f;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lw51/f;

    .line 10
    .line 11
    iget-object v0, p1, Lw51/f;->a:Lw51/b;

    .line 12
    .line 13
    iget-object v1, p0, Lw51/f;->a:Lw51/b;

    .line 14
    .line 15
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    iget-object v0, p0, Lw51/f;->b:Lw51/e;

    .line 23
    .line 24
    iget-object v1, p1, Lw51/f;->b:Lw51/e;

    .line 25
    .line 26
    if-eq v0, v1, :cond_3

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_3
    iget-object v0, p0, Lw51/f;->g:Ljava/lang/Throwable;

    .line 30
    .line 31
    iget-object v1, p1, Lw51/f;->g:Ljava/lang/Throwable;

    .line 32
    .line 33
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_4

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_4
    iget-object v0, p0, Lw51/f;->d:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v1, p1, Lw51/f;->d:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-nez v0, :cond_5

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_5
    iget v0, p0, Lw51/f;->e:I

    .line 52
    .line 53
    iget v1, p1, Lw51/f;->e:I

    .line 54
    .line 55
    if-eq v0, v1, :cond_6

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_6
    iget-object v0, p0, Lw51/f;->f:Ljava/lang/String;

    .line 59
    .line 60
    iget-object v1, p1, Lw51/f;->f:Ljava/lang/String;

    .line 61
    .line 62
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-nez v0, :cond_7

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_7
    iget-wide v0, p0, Lw51/f;->h:J

    .line 70
    .line 71
    iget-wide v2, p1, Lw51/f;->h:J

    .line 72
    .line 73
    cmp-long v0, v0, v2

    .line 74
    .line 75
    if-eqz v0, :cond_8

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_8
    sget-object v0, Lw51/c;->a:Lw51/b;

    .line 79
    .line 80
    iget-object p0, p0, Lw51/f;->c:Lay0/a;

    .line 81
    .line 82
    invoke-static {p0}, Lw51/c;->e(Lay0/a;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    iget-object p1, p1, Lw51/f;->c:Lay0/a;

    .line 87
    .line 88
    invoke-static {p1}, Lw51/c;->e(Lay0/a;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-nez p0, :cond_9

    .line 97
    .line 98
    :goto_0
    const/4 p0, 0x0

    .line 99
    return p0

    .line 100
    :cond_9
    :goto_1
    const/4 p0, 0x1

    .line 101
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lw51/f;->a:Lw51/b;

    .line 2
    .line 3
    iget-object v0, v0, Lw51/b;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/16 v1, 0x1f

    .line 10
    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-object v2, p0, Lw51/f;->b:Lw51/e;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    add-int/2addr v2, v0

    .line 19
    mul-int/2addr v2, v1

    .line 20
    const/4 v0, 0x0

    .line 21
    iget-object v3, p0, Lw51/f;->g:Ljava/lang/Throwable;

    .line 22
    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move v3, v0

    .line 31
    :goto_0
    add-int/2addr v2, v3

    .line 32
    mul-int/2addr v2, v1

    .line 33
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    iget-object v2, p0, Lw51/f;->d:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iget v2, p0, Lw51/f;->e:I

    .line 44
    .line 45
    add-int/2addr v0, v2

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-object v2, p0, Lw51/f;->f:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-wide v2, p0, Lw51/f;->h:J

    .line 54
    .line 55
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    sget-object v1, Lw51/c;->a:Lw51/b;

    .line 60
    .line 61
    iget-object p0, p0, Lw51/f;->c:Lay0/a;

    .line 62
    .line 63
    invoke-static {p0}, Lw51/c;->e(Lay0/a;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    add-int/2addr p0, v0

    .line 72
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    sget-object v0, Lw51/c;->a:Lw51/b;

    .line 2
    .line 3
    iget-object v0, p0, Lw51/f;->c:Lay0/a;

    .line 4
    .line 5
    invoke-static {v0}, Lw51/c;->e(Lay0/a;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v2, "LogMessage(millisTimestamp="

    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-wide v2, p0, Lw51/f;->h:J

    .line 17
    .line 18
    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v2, ", moduleName="

    .line 22
    .line 23
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    iget-object v2, p0, Lw51/f;->a:Lw51/b;

    .line 27
    .line 28
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v2, ", logLevel="

    .line 32
    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v2, p0, Lw51/f;->b:Lw51/e;

    .line 37
    .line 38
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v2, ", throwable="

    .line 42
    .line 43
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-object v2, p0, Lw51/f;->g:Ljava/lang/Throwable;

    .line 47
    .line 48
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v2, ", containsSensitiveInformation=false, message="

    .line 52
    .line 53
    const-string v3, ", className=\'"

    .line 54
    .line 55
    iget-object v4, p0, Lw51/f;->d:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v1, v2, v0, v3, v4}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    const-string v0, "\', lineNumber="

    .line 61
    .line 62
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    iget v0, p0, Lw51/f;->e:I

    .line 66
    .line 67
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v0, ", threadName=\'"

    .line 71
    .line 72
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    iget-object p0, p0, Lw51/f;->f:Ljava/lang/String;

    .line 76
    .line 77
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string p0, "\')"

    .line 81
    .line 82
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0
.end method
