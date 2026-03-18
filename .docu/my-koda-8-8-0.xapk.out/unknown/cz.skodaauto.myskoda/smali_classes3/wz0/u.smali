.class public final Lwz0/u;
.super Lwz0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lvz0/f;

.field public final g:I

.field public h:I


# direct methods
.method public constructor <init>(Lvz0/d;Lvz0/f;)V
    .locals 1

    .line 1
    const-string v0, "json"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "value"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-direct {p0, p1, v0}, Lwz0/a;-><init>(Lvz0/d;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iput-object p2, p0, Lwz0/u;->f:Lvz0/f;

    .line 16
    .line 17
    iget-object p1, p2, Lvz0/f;->d:Ljava/util/List;

    .line 18
    .line 19
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    iput p1, p0, Lwz0/u;->g:I

    .line 24
    .line 25
    const/4 p1, -0x1

    .line 26
    iput p1, p0, Lwz0/u;->h:I

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final E(Lsz0/g;)I
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget p1, p0, Lwz0/u;->h:I

    .line 7
    .line 8
    iget v0, p0, Lwz0/u;->g:I

    .line 9
    .line 10
    add-int/lit8 v0, v0, -0x1

    .line 11
    .line 12
    if-ge p1, v0, :cond_0

    .line 13
    .line 14
    add-int/lit8 p1, p1, 0x1

    .line 15
    .line 16
    iput p1, p0, Lwz0/u;->h:I

    .line 17
    .line 18
    return p1

    .line 19
    :cond_0
    const/4 p0, -0x1

    .line 20
    return p0
.end method

.method public final F(Ljava/lang/String;)Lvz0/n;
    .locals 1

    .line 1
    const-string v0, "tag"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iget-object p0, p0, Lwz0/u;->f:Lvz0/f;

    .line 11
    .line 12
    iget-object p0, p0, Lvz0/f;->d:Ljava/util/List;

    .line 13
    .line 14
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Lvz0/n;

    .line 19
    .line 20
    return-object p0
.end method

.method public final R(Lsz0/g;I)Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final T()Lvz0/n;
    .locals 0

    .line 1
    iget-object p0, p0, Lwz0/u;->f:Lvz0/f;

    .line 2
    .line 3
    return-object p0
.end method
