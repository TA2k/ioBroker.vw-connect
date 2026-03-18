.class public final Lm70/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lm70/a0;

.field public final b:Lvf0/a;

.field public final c:Ljava/lang/String;

.field public final d:Z


# direct methods
.method public constructor <init>(Lm70/a0;Lvf0/a;Ljava/lang/String;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm70/b0;->a:Lm70/a0;

    .line 5
    .line 6
    iput-object p2, p0, Lm70/b0;->b:Lvf0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lm70/b0;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-boolean p4, p0, Lm70/b0;->d:Z

    .line 11
    .line 12
    return-void
.end method

.method public static a(Lm70/b0;Lm70/a0;Lvf0/a;Ljava/lang/String;ZI)Lm70/b0;
    .locals 1

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lm70/b0;->a:Lm70/a0;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p5, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lm70/b0;->b:Lvf0/a;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p5, p5, 0x8

    .line 14
    .line 15
    if-eqz p5, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lm70/b0;->c:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    new-instance p0, Lm70/b0;

    .line 20
    .line 21
    invoke-direct {p0, p1, p2, p3, p4}, Lm70/b0;-><init>(Lm70/a0;Lvf0/a;Ljava/lang/String;Z)V

    .line 22
    .line 23
    .line 24
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
    instance-of v0, p1, Lm70/b0;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lm70/b0;

    .line 10
    .line 11
    iget-object v0, p0, Lm70/b0;->a:Lm70/a0;

    .line 12
    .line 13
    iget-object v1, p1, Lm70/b0;->a:Lm70/a0;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lm70/a0;->equals(Ljava/lang/Object;)Z

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
    iget-object v0, p0, Lm70/b0;->b:Lvf0/a;

    .line 23
    .line 24
    iget-object v1, p1, Lm70/b0;->b:Lvf0/a;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Lvf0/a;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_3

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_3
    iget-object v0, p0, Lm70/b0;->c:Ljava/lang/String;

    .line 34
    .line 35
    iget-object v1, p1, Lm70/b0;->c:Ljava/lang/String;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_4

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_4
    iget-boolean p0, p0, Lm70/b0;->d:Z

    .line 45
    .line 46
    iget-boolean p1, p1, Lm70/b0;->d:Z

    .line 47
    .line 48
    if-eq p0, p1, :cond_5

    .line 49
    .line 50
    :goto_0
    const/4 p0, 0x0

    .line 51
    return p0

    .line 52
    :cond_5
    :goto_1
    const/4 p0, 0x1

    .line 53
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lm70/b0;->a:Lm70/a0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lm70/a0;->hashCode()I

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
    iget-object v2, p0, Lm70/b0;->b:Lvf0/a;

    .line 11
    .line 12
    invoke-virtual {v2}, Lvf0/a;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/lit16 v2, v2, 0x3c1

    .line 18
    .line 19
    iget-object v0, p0, Lm70/b0;->c:Ljava/lang/String;

    .line 20
    .line 21
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    iget-boolean p0, p0, Lm70/b0;->d:Z

    .line 26
    .line 27
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State(headerData="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lm70/b0;->a:Lm70/a0;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", chartData="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lm70/b0;->b:Lvf0/a;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", selectedColumnIndex=null, unit="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", isLoading="

    .line 29
    .line 30
    const-string v2, ")"

    .line 31
    .line 32
    iget-object v3, p0, Lm70/b0;->c:Ljava/lang/String;

    .line 33
    .line 34
    iget-boolean p0, p0, Lm70/b0;->d:Z

    .line 35
    .line 36
    invoke-static {v3, v1, v2, v0, p0}, Lc1/j0;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method
