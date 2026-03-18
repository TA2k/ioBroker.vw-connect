.class public abstract Llp/xc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(ILk4/x;I)Lk4/c0;
    .locals 3

    .line 1
    new-instance v0, Lk4/c0;

    .line 2
    .line 3
    new-instance v1, Lk4/w;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    new-array v2, v2, [Lk4/v;

    .line 7
    .line 8
    invoke-direct {v1, v2}, Lk4/w;-><init>([Lk4/v;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {v0, p0, p1, p2, v1}, Lk4/c0;-><init>(ILk4/x;ILk4/w;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public static final b(Lw71/c;F)Lsv0/a;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lsv0/a;

    .line 7
    .line 8
    iget-wide v1, p0, Lw71/c;->b:D

    .line 9
    .line 10
    double-to-float v1, v1

    .line 11
    neg-float v1, v1

    .line 12
    iget-wide v2, p0, Lw71/c;->a:D

    .line 13
    .line 14
    double-to-float p0, v2

    .line 15
    invoke-direct {v0, v1, p0, p1}, Lsv0/a;-><init>(FFF)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method
