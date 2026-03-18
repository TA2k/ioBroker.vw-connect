.class public final Lh2/x9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh2/t9;


# instance fields
.field public final a:Lh2/y9;

.field public final b:Lvy0/l;


# direct methods
.method public constructor <init>(Lh2/y9;Lvy0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/x9;->a:Lh2/y9;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/x9;->b:Lvy0/l;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Lh2/y9;
    .locals 0

    .line 1
    iget-object p0, p0, Lh2/x9;->a:Lh2/y9;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()V
    .locals 1

    .line 1
    iget-object p0, p0, Lh2/x9;->b:Lvy0/l;

    .line 2
    .line 3
    invoke-virtual {p0}, Lvy0/l;->v()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Lh2/ka;->e:Lh2/ka;

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final dismiss()V
    .locals 1

    .line 1
    iget-object p0, p0, Lh2/x9;->b:Lvy0/l;

    .line 2
    .line 3
    invoke-virtual {p0}, Lvy0/l;->v()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Lh2/ka;->d:Lh2/ka;

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    if-eqz p1, :cond_4

    .line 5
    .line 6
    const-class v0, Lh2/x9;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    if-eq v0, v1, :cond_1

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_1
    check-cast p1, Lh2/x9;

    .line 16
    .line 17
    iget-object v0, p0, Lh2/x9;->a:Lh2/y9;

    .line 18
    .line 19
    iget-object v1, p1, Lh2/x9;->a:Lh2/y9;

    .line 20
    .line 21
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_2

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_2
    iget-object p0, p0, Lh2/x9;->b:Lvy0/l;

    .line 29
    .line 30
    iget-object p1, p1, Lh2/x9;->b:Lvy0/l;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-nez p0, :cond_3

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 40
    return p0

    .line 41
    :cond_4
    :goto_1
    const/4 p0, 0x0

    .line 42
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lh2/x9;->a:Lh2/y9;

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
    iget-object p0, p0, Lh2/x9;->b:Lvy0/l;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method
