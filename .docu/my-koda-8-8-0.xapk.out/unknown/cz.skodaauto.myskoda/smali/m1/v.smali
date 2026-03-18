.class public abstract Lm1/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lm1/l;


# direct methods
.method static constructor <clinit>()V
    .locals 19

    .line 1
    new-instance v5, Lm1/u;

    .line 2
    .line 3
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v16, Lg1/w1;->d:Lg1/w1;

    .line 7
    .line 8
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 9
    .line 10
    invoke-static {v0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 11
    .line 12
    .line 13
    move-result-object v8

    .line 14
    invoke-static {}, Lkp/b9;->a()Lt4/d;

    .line 15
    .line 16
    .line 17
    move-result-object v9

    .line 18
    const/4 v0, 0x0

    .line 19
    const/16 v1, 0xf

    .line 20
    .line 21
    invoke-static {v0, v0, v1}, Lt4/b;->b(III)J

    .line 22
    .line 23
    .line 24
    move-result-wide v10

    .line 25
    new-instance v0, Lm1/l;

    .line 26
    .line 27
    const/16 v17, 0x0

    .line 28
    .line 29
    const/16 v18, 0x0

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    const/4 v2, 0x0

    .line 33
    const/4 v3, 0x0

    .line 34
    const/4 v4, 0x0

    .line 35
    const/4 v6, 0x0

    .line 36
    const/4 v7, 0x0

    .line 37
    sget-object v12, Lmx0/s;->d:Lmx0/s;

    .line 38
    .line 39
    const/4 v13, 0x0

    .line 40
    const/4 v14, 0x0

    .line 41
    const/4 v15, 0x0

    .line 42
    invoke-direct/range {v0 .. v18}, Lm1/l;-><init>(Lm1/m;IZFLt3/r0;FZLvy0/b0;Lt4/c;JLjava/util/List;IIILg1/w1;II)V

    .line 43
    .line 44
    .line 45
    sput-object v0, Lm1/v;->a:Lm1/l;

    .line 46
    .line 47
    return-void
.end method

.method public static final a(IILl2/o;)Lm1/t;
    .locals 4

    .line 1
    and-int/lit8 p1, p1, 0x1

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    move p0, v0

    .line 7
    :cond_0
    new-array p1, v0, [Ljava/lang/Object;

    .line 8
    .line 9
    sget-object v1, Lm1/t;->x:Lu2/l;

    .line 10
    .line 11
    move-object v2, p2

    .line 12
    check-cast v2, Ll2/t;

    .line 13
    .line 14
    invoke-virtual {v2, p0}, Ll2/t;->e(I)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    move-object v3, p2

    .line 19
    check-cast v3, Ll2/t;

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    or-int/2addr v2, v3

    .line 26
    check-cast p2, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    if-nez v2, :cond_1

    .line 33
    .line 34
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 35
    .line 36
    if-ne v3, v2, :cond_2

    .line 37
    .line 38
    :cond_1
    new-instance v3, Le1/h1;

    .line 39
    .line 40
    const/4 v2, 0x2

    .line 41
    invoke-direct {v3, p0, v2}, Le1/h1;-><init>(II)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    check-cast v3, Lay0/a;

    .line 48
    .line 49
    invoke-static {p1, v1, v3, p2, v0}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lm1/t;

    .line 54
    .line 55
    return-object p0
.end method
