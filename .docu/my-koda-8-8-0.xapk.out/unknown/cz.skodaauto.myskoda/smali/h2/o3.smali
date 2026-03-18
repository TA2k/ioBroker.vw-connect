.class public final Lh2/o3;
.super Lh2/s;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Ll2/j1;

.field public final g:Ll2/j1;


# direct methods
.method public constructor <init>(Ljava/lang/Long;Ljava/lang/Long;Lgy0/j;ILh2/e8;Ljava/util/Locale;)V
    .locals 2

    .line 1
    invoke-direct {p0, p2, p3, p5, p6}, Lh2/s;-><init>(Ljava/lang/Long;Lgy0/j;Lh2/e8;Ljava/util/Locale;)V

    .line 2
    .line 3
    .line 4
    const/4 p2, 0x0

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    iget-object p5, p0, Lh2/s;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p5, Li2/b0;

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    invoke-virtual {p5, v0, v1}, Li2/b0;->a(J)Li2/y;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iget p5, p1, Li2/y;->d:I

    .line 20
    .line 21
    invoke-virtual {p3, p5}, Lgy0/j;->i(I)Z

    .line 22
    .line 23
    .line 24
    move-result p3

    .line 25
    if-eqz p3, :cond_0

    .line 26
    .line 27
    move-object p2, p1

    .line 28
    :cond_0
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iput-object p1, p0, Lh2/o3;->f:Ll2/j1;

    .line 33
    .line 34
    new-instance p1, Lh2/o4;

    .line 35
    .line 36
    invoke-direct {p1, p4}, Lh2/o4;-><init>(I)V

    .line 37
    .line 38
    .line 39
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    iput-object p1, p0, Lh2/o3;->g:Ll2/j1;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final f()I
    .locals 0

    .line 1
    iget-object p0, p0, Lh2/o3;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lh2/o4;

    .line 8
    .line 9
    iget p0, p0, Lh2/o4;->a:I

    .line 10
    .line 11
    return p0
.end method

.method public final g()Ljava/lang/Long;
    .locals 2

    .line 1
    iget-object p0, p0, Lh2/o3;->f:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li2/y;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    iget-wide v0, p0, Li2/y;->g:J

    .line 12
    .line 13
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return-object p0
.end method
