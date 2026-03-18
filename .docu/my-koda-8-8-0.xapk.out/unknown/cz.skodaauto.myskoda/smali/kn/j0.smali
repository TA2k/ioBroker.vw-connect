.class public final Lkn/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Lx4/x;

.field public final c:I

.field public final d:Z

.field public final e:J

.field public final f:J


# direct methods
.method public constructor <init>(ZLx4/x;IZJJ)V
    .locals 1

    .line 1
    const-string v0, "dialogSecurePolicy"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-boolean p1, p0, Lkn/j0;->a:Z

    .line 10
    .line 11
    iput-object p2, p0, Lkn/j0;->b:Lx4/x;

    .line 12
    .line 13
    iput p3, p0, Lkn/j0;->c:I

    .line 14
    .line 15
    iput-boolean p4, p0, Lkn/j0;->d:Z

    .line 16
    .line 17
    iput-wide p5, p0, Lkn/j0;->e:J

    .line 18
    .line 19
    iput-wide p7, p0, Lkn/j0;->f:J

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)Z
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
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    if-eqz p1, :cond_1

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    goto :goto_0

    .line 16
    :cond_1
    const/4 v2, 0x0

    .line 17
    :goto_0
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_2
    const-string v1, "null cannot be cast to non-null type com.dokar.sheets.SheetBehaviors"

    .line 25
    .line 26
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    check-cast p1, Lkn/j0;

    .line 30
    .line 31
    iget-boolean p0, p0, Lkn/j0;->a:Z

    .line 32
    .line 33
    iget-boolean p1, p1, Lkn/j0;->a:Z

    .line 34
    .line 35
    if-eq p0, p1, :cond_3

    .line 36
    .line 37
    :goto_1
    const/4 p0, 0x0

    .line 38
    return p0

    .line 39
    :cond_3
    return v0
.end method

.method public final b()I
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    const/16 v1, 0x1f

    .line 7
    .line 8
    mul-int/2addr v0, v1

    .line 9
    iget-boolean p0, p0, Lkn/j0;->a:Z

    .line 10
    .line 11
    invoke-static {v0, v1, p0}, La7/g0;->e(IIZ)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    const/4 v0, 0x0

    .line 16
    invoke-static {p0, v1, v0}, La7/g0;->e(IIZ)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, p0

    .line 25
    return v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_2

    .line 4
    :cond_0
    if-eqz p1, :cond_1

    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    goto :goto_0

    .line 11
    :cond_1
    const/4 v0, 0x0

    .line 12
    :goto_0
    const-class v1, Lkn/j0;

    .line 13
    .line 14
    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_2

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_2
    invoke-virtual {p0, p1}, Lkn/j0;->a(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_3

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_3
    const-string v0, "null cannot be cast to non-null type com.dokar.sheets.DialogSheetBehaviors"

    .line 29
    .line 30
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    check-cast p1, Lkn/j0;

    .line 34
    .line 35
    iget-object v0, p0, Lkn/j0;->b:Lx4/x;

    .line 36
    .line 37
    iget-object v1, p1, Lkn/j0;->b:Lx4/x;

    .line 38
    .line 39
    if-eq v0, v1, :cond_4

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_4
    iget v0, p0, Lkn/j0;->c:I

    .line 43
    .line 44
    iget v1, p1, Lkn/j0;->c:I

    .line 45
    .line 46
    if-eq v0, v1, :cond_5

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_5
    iget-boolean v0, p0, Lkn/j0;->d:Z

    .line 50
    .line 51
    iget-boolean v1, p1, Lkn/j0;->d:Z

    .line 52
    .line 53
    if-eq v0, v1, :cond_6

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_6
    iget-wide v0, p0, Lkn/j0;->e:J

    .line 57
    .line 58
    iget-wide v2, p1, Lkn/j0;->e:J

    .line 59
    .line 60
    invoke-static {v0, v1, v2, v3}, Le3/s;->c(JJ)Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-nez v0, :cond_7

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_7
    iget-wide v0, p0, Lkn/j0;->f:J

    .line 68
    .line 69
    iget-wide p0, p1, Lkn/j0;->f:J

    .line 70
    .line 71
    invoke-static {v0, v1, p0, p1}, Le3/s;->c(JJ)Z

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    if-nez p0, :cond_8

    .line 76
    .line 77
    :goto_1
    const/4 p0, 0x0

    .line 78
    return p0

    .line 79
    :cond_8
    :goto_2
    const/4 p0, 0x1

    .line 80
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    invoke-virtual {p0}, Lkn/j0;->b()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x1f

    .line 6
    .line 7
    mul-int/2addr v0, v1

    .line 8
    iget-object v2, p0, Lkn/j0;->b:Lx4/x;

    .line 9
    .line 10
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    add-int/2addr v2, v0

    .line 15
    mul-int/2addr v2, v1

    .line 16
    iget v0, p0, Lkn/j0;->c:I

    .line 17
    .line 18
    add-int/2addr v2, v0

    .line 19
    mul-int/2addr v2, v1

    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    iget-boolean v2, p0, Lkn/j0;->d:Z

    .line 26
    .line 27
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    sget v2, Le3/s;->j:I

    .line 32
    .line 33
    iget-wide v2, p0, Lkn/j0;->e:J

    .line 34
    .line 35
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    iget-wide v1, p0, Lkn/j0;->f:J

    .line 40
    .line 41
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    add-int/2addr p0, v0

    .line 46
    return p0
.end method
