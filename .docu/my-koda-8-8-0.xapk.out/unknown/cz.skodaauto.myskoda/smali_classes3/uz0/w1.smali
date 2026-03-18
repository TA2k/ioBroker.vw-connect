.class public final Luz0/w1;
.super Luz0/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Luz0/w1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Luz0/w1;

    .line 2
    .line 3
    sget-object v1, Luz0/x1;->a:Luz0/x1;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Luz0/g1;-><init>(Lqz0/a;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Luz0/w1;->c:Luz0/w1;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final d(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Llx0/v;

    .line 2
    .line 3
    iget-object p0, p1, Llx0/v;->d:[I

    .line 4
    .line 5
    const-string p1, "$this$collectionSize"

    .line 6
    .line 7
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    array-length p0, p0

    .line 11
    return p0
.end method

.method public final f(Ltz0/a;ILjava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p3, Luz0/v1;

    .line 2
    .line 3
    const-string v0, "builder"

    .line 4
    .line 5
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Luz0/g1;->b:Luz0/f1;

    .line 9
    .line 10
    invoke-interface {p1, p0, p2}, Ltz0/a;->j(Luz0/f1;I)Ltz0/c;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Ltz0/c;->i()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    invoke-static {p3}, Luz0/e1;->c(Luz0/e1;)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p3, Luz0/v1;->a:[I

    .line 22
    .line 23
    iget p2, p3, Luz0/v1;->b:I

    .line 24
    .line 25
    add-int/lit8 v0, p2, 0x1

    .line 26
    .line 27
    iput v0, p3, Luz0/v1;->b:I

    .line 28
    .line 29
    aput p0, p1, p2

    .line 30
    .line 31
    return-void
.end method

.method public final g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/v;

    .line 2
    .line 3
    iget-object p0, p1, Llx0/v;->d:[I

    .line 4
    .line 5
    const-string p1, "$this$toBuilder"

    .line 6
    .line 7
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance p1, Luz0/v1;

    .line 11
    .line 12
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p0, p1, Luz0/v1;->a:[I

    .line 16
    .line 17
    array-length p0, p0

    .line 18
    iput p0, p1, Luz0/v1;->b:I

    .line 19
    .line 20
    const/16 p0, 0xa

    .line 21
    .line 22
    invoke-virtual {p1, p0}, Luz0/v1;->b(I)V

    .line 23
    .line 24
    .line 25
    return-object p1
.end method

.method public final j()Ljava/lang/Object;
    .locals 1

    .line 1
    const/4 p0, 0x0

    .line 2
    new-array p0, p0, [I

    .line 3
    .line 4
    new-instance v0, Llx0/v;

    .line 5
    .line 6
    invoke-direct {v0, p0}, Llx0/v;-><init>([I)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

.method public final k(Ltz0/b;Ljava/lang/Object;I)V
    .locals 3

    .line 1
    check-cast p2, Llx0/v;

    .line 2
    .line 3
    iget-object p2, p2, Llx0/v;->d:[I

    .line 4
    .line 5
    const-string v0, "encoder"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    :goto_0
    if-ge v0, p3, :cond_0

    .line 12
    .line 13
    iget-object v1, p0, Luz0/g1;->b:Luz0/f1;

    .line 14
    .line 15
    invoke-interface {p1, v1, v0}, Ltz0/b;->l(Luz0/f1;I)Ltz0/d;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    aget v2, p2, v0

    .line 20
    .line 21
    invoke-interface {v1, v2}, Ltz0/d;->B(I)V

    .line 22
    .line 23
    .line 24
    add-int/lit8 v0, v0, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    return-void
.end method
