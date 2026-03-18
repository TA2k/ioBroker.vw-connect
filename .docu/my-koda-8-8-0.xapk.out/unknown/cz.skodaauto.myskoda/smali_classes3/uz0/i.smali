.class public final Luz0/i;
.super Luz0/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Luz0/i;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Luz0/i;

    .line 2
    .line 3
    sget-object v1, Luz0/j;->a:Luz0/j;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Luz0/g1;-><init>(Lqz0/a;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Luz0/i;->c:Luz0/i;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final d(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, [B

    .line 2
    .line 3
    const-string p0, "<this>"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    array-length p0, p1

    .line 9
    return p0
.end method

.method public final f(Ltz0/a;ILjava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p3, Luz0/h;

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
    invoke-interface {p1, p0, p2}, Ltz0/a;->v(Lsz0/g;I)B

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    invoke-static {p3}, Luz0/e1;->c(Luz0/e1;)V

    .line 15
    .line 16
    .line 17
    iget-object p1, p3, Luz0/h;->a:[B

    .line 18
    .line 19
    iget p2, p3, Luz0/h;->b:I

    .line 20
    .line 21
    add-int/lit8 v0, p2, 0x1

    .line 22
    .line 23
    iput v0, p3, Luz0/h;->b:I

    .line 24
    .line 25
    aput-byte p0, p1, p2

    .line 26
    .line 27
    return-void
.end method

.method public final g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, [B

    .line 2
    .line 3
    const-string p0, "<this>"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance p0, Luz0/h;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Luz0/h;->a:[B

    .line 14
    .line 15
    array-length p1, p1

    .line 16
    iput p1, p0, Luz0/h;->b:I

    .line 17
    .line 18
    const/16 p1, 0xa

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Luz0/h;->b(I)V

    .line 21
    .line 22
    .line 23
    return-object p0
.end method

.method public final j()Ljava/lang/Object;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    new-array p0, p0, [B

    .line 3
    .line 4
    return-object p0
.end method

.method public final k(Ltz0/b;Ljava/lang/Object;I)V
    .locals 3

    .line 1
    check-cast p2, [B

    .line 2
    .line 3
    const-string v0, "encoder"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "content"

    .line 9
    .line 10
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    :goto_0
    if-ge v0, p3, :cond_0

    .line 15
    .line 16
    iget-object v1, p0, Luz0/g1;->b:Luz0/f1;

    .line 17
    .line 18
    aget-byte v2, p2, v0

    .line 19
    .line 20
    invoke-interface {p1, v1, v0, v2}, Ltz0/b;->o(Lsz0/g;IB)V

    .line 21
    .line 22
    .line 23
    add-int/lit8 v0, v0, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    return-void
.end method
