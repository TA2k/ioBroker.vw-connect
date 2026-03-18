.class public abstract Ln1/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ln1/n;


# direct methods
.method static constructor <clinit>()V
    .locals 20

    .line 1
    new-instance v5, Ln1/w;

    .line 2
    .line 3
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v17, Lg1/w1;->d:Lg1/w1;

    .line 7
    .line 8
    invoke-static {}, Lkp/b9;->a()Lt4/d;

    .line 9
    .line 10
    .line 11
    move-result-object v9

    .line 12
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 13
    .line 14
    invoke-static {v0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 15
    .line 16
    .line 17
    move-result-object v8

    .line 18
    new-instance v0, Ln1/n;

    .line 19
    .line 20
    new-instance v11, Lmj/g;

    .line 21
    .line 22
    const/16 v1, 0xe

    .line 23
    .line 24
    invoke-direct {v11, v1}, Lmj/g;-><init>(I)V

    .line 25
    .line 26
    .line 27
    new-instance v12, Lmj/g;

    .line 28
    .line 29
    const/16 v1, 0xf

    .line 30
    .line 31
    invoke-direct {v12, v1}, Lmj/g;-><init>(I)V

    .line 32
    .line 33
    .line 34
    const/16 v18, 0x0

    .line 35
    .line 36
    const/16 v19, 0x0

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    const/4 v2, 0x0

    .line 40
    const/4 v3, 0x0

    .line 41
    const/4 v4, 0x0

    .line 42
    const/4 v6, 0x0

    .line 43
    const/4 v7, 0x0

    .line 44
    const/4 v10, 0x0

    .line 45
    sget-object v13, Lmx0/s;->d:Lmx0/s;

    .line 46
    .line 47
    const/4 v14, 0x0

    .line 48
    const/4 v15, 0x0

    .line 49
    const/16 v16, 0x0

    .line 50
    .line 51
    invoke-direct/range {v0 .. v19}, Ln1/n;-><init>(Ln1/p;IZFLt3/r0;FZLvy0/b0;Lt4/c;ILay0/k;Lay0/k;Ljava/util/List;IIILg1/w1;II)V

    .line 52
    .line 53
    .line 54
    sput-object v0, Ln1/x;->a:Ln1/n;

    .line 55
    .line 56
    return-void
.end method

.method public static final a(IILl2/o;)Ln1/v;
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
    sget-object v1, Ln1/v;->w:Lu2/l;

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
    const/4 v2, 0x3

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
    check-cast p0, Ln1/v;

    .line 54
    .line 55
    return-object p0
.end method
