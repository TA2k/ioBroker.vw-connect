.class public final Ltl/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lul/h;

.field public final b:Lul/f;

.field public final c:Lwl/e;

.field public final d:Lul/d;


# direct methods
.method public constructor <init>(Lul/h;Lul/f;Lwl/e;Lul/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltl/c;->a:Lul/h;

    .line 5
    .line 6
    iput-object p2, p0, Ltl/c;->b:Lul/f;

    .line 7
    .line 8
    iput-object p3, p0, Ltl/c;->c:Lwl/e;

    .line 9
    .line 10
    iput-object p4, p0, Ltl/c;->d:Lul/d;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
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
    instance-of v1, p1, Ltl/c;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    check-cast p1, Ltl/c;

    .line 10
    .line 11
    iget-object v1, p0, Ltl/c;->a:Lul/h;

    .line 12
    .line 13
    iget-object v2, p1, Ltl/c;->a:Lul/h;

    .line 14
    .line 15
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    iget-object v1, p0, Ltl/c;->b:Lul/f;

    .line 22
    .line 23
    iget-object v2, p1, Ltl/c;->b:Lul/f;

    .line 24
    .line 25
    if-ne v1, v2, :cond_1

    .line 26
    .line 27
    iget-object v1, p0, Ltl/c;->c:Lwl/e;

    .line 28
    .line 29
    iget-object v2, p1, Ltl/c;->c:Lwl/e;

    .line 30
    .line 31
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_1

    .line 36
    .line 37
    iget-object p0, p0, Ltl/c;->d:Lul/d;

    .line 38
    .line 39
    iget-object p1, p1, Ltl/c;->d:Lul/d;

    .line 40
    .line 41
    if-ne p0, p1, :cond_1

    .line 42
    .line 43
    return v0

    .line 44
    :cond_1
    const/4 p0, 0x0

    .line 45
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ltl/c;->a:Lul/h;

    .line 3
    .line 4
    if-eqz v1, :cond_0

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v1, v0

    .line 12
    :goto_0
    mul-int/lit8 v1, v1, 0x1f

    .line 13
    .line 14
    iget-object v2, p0, Ltl/c;->b:Lul/f;

    .line 15
    .line 16
    if-eqz v2, :cond_1

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move v2, v0

    .line 24
    :goto_1
    add-int/2addr v1, v2

    .line 25
    const v2, 0x1b4d89f

    .line 26
    .line 27
    .line 28
    mul-int/2addr v1, v2

    .line 29
    iget-object v2, p0, Ltl/c;->c:Lwl/e;

    .line 30
    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    goto :goto_2

    .line 38
    :cond_2
    move v2, v0

    .line 39
    :goto_2
    add-int/2addr v1, v2

    .line 40
    mul-int/lit8 v1, v1, 0x1f

    .line 41
    .line 42
    iget-object p0, p0, Ltl/c;->d:Lul/d;

    .line 43
    .line 44
    if-eqz p0, :cond_3

    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    :cond_3
    add-int/2addr v1, v0

    .line 51
    const p0, 0x34e63b41

    .line 52
    .line 53
    .line 54
    mul-int/2addr v1, p0

    .line 55
    return v1
.end method
