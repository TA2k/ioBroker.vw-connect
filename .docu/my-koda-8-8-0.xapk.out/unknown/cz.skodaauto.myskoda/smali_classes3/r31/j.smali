.class public final Lr31/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lq41/a;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Z

.field public final c:Z

.field public final d:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;ZZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr31/j;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-boolean p2, p0, Lr31/j;->b:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lr31/j;->c:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lr31/j;->d:Z

    .line 11
    .line 12
    return-void
.end method

.method public static a(Lr31/j;Ljava/lang/String;ZZI)Lr31/j;
    .locals 1

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lr31/j;->a:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    and-int/lit8 v0, p4, 0x4

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-boolean p2, p0, Lr31/j;->b:Z

    .line 15
    .line 16
    :cond_1
    and-int/lit8 v0, p4, 0x8

    .line 17
    .line 18
    if-eqz v0, :cond_2

    .line 19
    .line 20
    iget-boolean v0, p0, Lr31/j;->c:Z

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_2
    const/4 v0, 0x0

    .line 24
    :goto_0
    and-int/lit8 p4, p4, 0x10

    .line 25
    .line 26
    if-eqz p4, :cond_3

    .line 27
    .line 28
    iget-boolean p3, p0, Lr31/j;->d:Z

    .line 29
    .line 30
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    new-instance p0, Lr31/j;

    .line 34
    .line 35
    invoke-direct {p0, p1, p2, v0, p3}, Lr31/j;-><init>(Ljava/lang/String;ZZZ)V

    .line 36
    .line 37
    .line 38
    return-object p0
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
    instance-of v0, p1, Lr31/j;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lr31/j;

    .line 10
    .line 11
    iget-object v0, p0, Lr31/j;->a:Ljava/lang/String;

    .line 12
    .line 13
    iget-object v1, p1, Lr31/j;->a:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

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
    iget-boolean v0, p0, Lr31/j;->b:Z

    .line 23
    .line 24
    iget-boolean v1, p1, Lr31/j;->b:Z

    .line 25
    .line 26
    if-eq v0, v1, :cond_3

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_3
    iget-boolean v0, p0, Lr31/j;->c:Z

    .line 30
    .line 31
    iget-boolean v1, p1, Lr31/j;->c:Z

    .line 32
    .line 33
    if-eq v0, v1, :cond_4

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_4
    iget-boolean p0, p0, Lr31/j;->d:Z

    .line 37
    .line 38
    iget-boolean p1, p1, Lr31/j;->d:Z

    .line 39
    .line 40
    if-eq p0, p1, :cond_5

    .line 41
    .line 42
    :goto_0
    const/4 p0, 0x0

    .line 43
    return p0

    .line 44
    :cond_5
    :goto_1
    const/4 p0, 0x1

    .line 45
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lr31/j;->a:Ljava/lang/String;

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
    const/16 v2, 0xf

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lr31/j;->b:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lr31/j;->c:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean p0, p0, Lr31/j;->d:Z

    .line 29
    .line 30
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, v0

    .line 35
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", licenseCharLimit=15, isContinueButtonEnabled="

    .line 2
    .line 3
    const-string v1, ", isSkipButtonVisible="

    .line 4
    .line 5
    const-string v2, "LicensePlateViewState(inputText="

    .line 6
    .line 7
    iget-object v3, p0, Lr31/j;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, p0, Lr31/j;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v1, v4}, Lia/b;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", requestTextFieldFocus="

    .line 16
    .line 17
    const-string v2, ")"

    .line 18
    .line 19
    iget-boolean v3, p0, Lr31/j;->c:Z

    .line 20
    .line 21
    iget-boolean p0, p0, Lr31/j;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
