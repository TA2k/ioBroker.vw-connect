.class public final Lht/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lht/i;


# instance fields
.field public final a:Lht/j;

.field public final b:Laq/k;


# direct methods
.method public constructor <init>(Lht/j;Laq/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lht/f;->a:Lht/j;

    .line 5
    .line 6
    iput-object p2, p0, Lht/f;->b:Laq/k;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Exception;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lht/f;->b:Laq/k;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0
.end method

.method public final b(Ljt/b;)Z
    .locals 7

    .line 1
    iget v0, p1, Ljt/b;->b:I

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    if-ne v0, v1, :cond_1

    .line 5
    .line 6
    iget-object v0, p0, Lht/f;->a:Lht/j;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lht/j;->a(Ljt/b;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    iget-object v4, p1, Ljt/b;->c:Ljava/lang/String;

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    iget-wide v2, p1, Ljt/b;->e:J

    .line 19
    .line 20
    iget-wide v5, p1, Ljt/b;->f:J

    .line 21
    .line 22
    new-instance v1, Lht/a;

    .line 23
    .line 24
    invoke-direct/range {v1 .. v6}, Lht/a;-><init>(JLjava/lang/String;J)V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lht/f;->b:Laq/k;

    .line 28
    .line 29
    invoke-virtual {p0, v1}, Laq/k;->b(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    const/4 p0, 0x1

    .line 33
    return p0

    .line 34
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 35
    .line 36
    const-string p1, "Null token"

    .line 37
    .line 38
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_1
    const/4 p0, 0x0

    .line 43
    return p0
.end method
