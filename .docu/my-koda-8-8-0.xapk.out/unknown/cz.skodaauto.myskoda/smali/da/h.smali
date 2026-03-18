.class public final Lda/h;
.super Llp/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lqz0/a;

.field public final b:Ljava/util/LinkedHashMap;

.field public final c:Lwq/f;

.field public final d:Ljava/util/LinkedHashMap;

.field public e:I


# direct methods
.method public constructor <init>(Lqz0/a;Ljava/util/LinkedHashMap;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lda/h;->a:Lqz0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lda/h;->b:Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    sget-object p1, Lxz0/a;->a:Lwq/f;

    .line 9
    .line 10
    iput-object p1, p0, Lda/h;->c:Lwq/f;

    .line 11
    .line 12
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 13
    .line 14
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lda/h;->d:Ljava/util/LinkedHashMap;

    .line 18
    .line 19
    const/4 p1, -0x1

    .line 20
    iput p1, p0, Lda/h;->e:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final D(Lqz0/a;Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "serializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p2}, Lda/h;->I(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final G(Lsz0/g;I)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput p2, p0, Lda/h;->e:I

    .line 7
    .line 8
    return-void
.end method

.method public final H(Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lda/h;->I(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final I(Ljava/lang/Object;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lda/h;->a:Lqz0/a;

    .line 2
    .line 3
    invoke-interface {v0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget v1, p0, Lda/h;->e:I

    .line 8
    .line 9
    invoke-interface {v0, v1}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v1, p0, Lda/h;->b:Ljava/util/LinkedHashMap;

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lz9/g0;

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    instance-of v2, v1, Lz9/f;

    .line 24
    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    check-cast v1, Lz9/f;

    .line 28
    .line 29
    invoke-virtual {v1, p1}, Lz9/f;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {v1, p1}, Lz9/g0;->f(Ljava/lang/Object;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    :goto_0
    iget-object p0, p0, Lda/h;->d:Ljava/util/LinkedHashMap;

    .line 43
    .line 44
    invoke-interface {p0, v0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_1
    const-string p0, "Cannot find NavType for argument "

    .line 49
    .line 50
    const-string p1, ". Please provide NavType through typeMap."

    .line 51
    .line 52
    invoke-static {p0, v0, p1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p1
.end method

.method public final c()Lwq/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lda/h;->c:Lwq/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j(Lsz0/g;)Ltz0/d;
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lda/d;->f(Lsz0/g;)Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    iput p1, p0, Lda/h;->e:I

    .line 14
    .line 15
    :cond_0
    return-object p0
.end method

.method public final p()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lda/h;->I(Ljava/lang/Object;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method
