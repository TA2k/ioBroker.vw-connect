.class public final Lwk0/p2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z


# direct methods
.method public synthetic constructor <init>(IZZZ)V
    .locals 2

    and-int/lit8 v0, p1, 0x1

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move p2, v1

    :cond_0
    and-int/lit8 p1, p1, 0x4

    if-eqz p1, :cond_1

    const/4 p3, 0x1

    .line 1
    :cond_1
    invoke-direct {p0, p2, v1, p3, p4}, Lwk0/p2;-><init>(ZZZZ)V

    return-void
.end method

.method public constructor <init>(ZZZZ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Lwk0/p2;->a:Z

    .line 4
    iput-boolean p2, p0, Lwk0/p2;->b:Z

    .line 5
    iput-boolean p3, p0, Lwk0/p2;->c:Z

    .line 6
    iput-boolean p4, p0, Lwk0/p2;->d:Z

    return-void
.end method

.method public static a(Lwk0/p2;Z)Lwk0/p2;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lwk0/p2;->a:Z

    .line 2
    .line 3
    iget-boolean v1, p0, Lwk0/p2;->c:Z

    .line 4
    .line 5
    iget-boolean v2, p0, Lwk0/p2;->d:Z

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    new-instance p0, Lwk0/p2;

    .line 11
    .line 12
    invoke-direct {p0, v0, p1, v1, v2}, Lwk0/p2;-><init>(ZZZZ)V

    .line 13
    .line 14
    .line 15
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
    instance-of v0, p1, Lwk0/p2;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lwk0/p2;

    .line 10
    .line 11
    iget-boolean v0, p0, Lwk0/p2;->a:Z

    .line 12
    .line 13
    iget-boolean v1, p1, Lwk0/p2;->a:Z

    .line 14
    .line 15
    if-eq v0, v1, :cond_2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    iget-boolean v0, p0, Lwk0/p2;->b:Z

    .line 19
    .line 20
    iget-boolean v1, p1, Lwk0/p2;->b:Z

    .line 21
    .line 22
    if-eq v0, v1, :cond_3

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_3
    iget-boolean v0, p0, Lwk0/p2;->c:Z

    .line 26
    .line 27
    iget-boolean v1, p1, Lwk0/p2;->c:Z

    .line 28
    .line 29
    if-eq v0, v1, :cond_4

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_4
    iget-boolean p0, p0, Lwk0/p2;->d:Z

    .line 33
    .line 34
    iget-boolean p1, p1, Lwk0/p2;->d:Z

    .line 35
    .line 36
    if-eq p0, p1, :cond_5

    .line 37
    .line 38
    :goto_0
    const/4 p0, 0x0

    .line 39
    return p0

    .line 40
    :cond_5
    :goto_1
    const/4 p0, 0x1

    .line 41
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lwk0/p2;->a:Z

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
    iget-boolean v2, p0, Lwk0/p2;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lwk0/p2;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean p0, p0, Lwk0/p2;->d:Z

    .line 23
    .line 24
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isSelectServiceDialogVisible="

    .line 2
    .line 3
    const-string v1, ", isSelectServicePartnerEnabled="

    .line 4
    .line 5
    const-string v2, "DetailState(isPreferredServicePartner="

    .line 6
    .line 7
    iget-boolean v3, p0, Lwk0/p2;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lwk0/p2;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isServicePartnerActionVisible="

    .line 16
    .line 17
    const-string v2, ")"

    .line 18
    .line 19
    iget-boolean v3, p0, Lwk0/p2;->c:Z

    .line 20
    .line 21
    iget-boolean p0, p0, Lwk0/p2;->d:Z

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
